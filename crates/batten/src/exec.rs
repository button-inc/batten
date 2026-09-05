//! `batten exec -- <cmd> …`: run a command and get out of the way (CLOUD-285).
//!
//! House style §2 has listed this verb since the surface was designed, and two
//! Phase 2 issues are built on it — [`crate::hook`]'s siblings CLOUD-162 (capture
//! its output) and CLOUD-117 (promote a lying exit `0` to a violation). Neither
//! could be built, because the verb did not exist.
//!
//! ## Transparent, which is a stronger claim than "thin"
//!
//! Three things pass through untouched, and each is load-bearing for a consumer:
//!
//! * **The child's argv.** Declared as [`crate::surface::ValueDecl::Trailing`],
//!   which sets `trailing_var_arg(true)` and `allow_hyphen_values(true)`. The
//!   second is not defensive tidying: without
//!   it a wrapped command's own `-v` is parsed as Batten's §3 verbosity rung, so
//!   `batten exec -- cargo test -v` would raise Batten's log level and drop the
//!   flag the caller meant for `cargo`.
//! * **The child's streams**, on request. Each stream is drained to the store
//!   always (CLOUD-162) and copied to Batten's corresponding stream **under
//!   `--tee`** (CLOUD-429), where the copy is byte-for-byte what the child wrote.
//!   The default is a record instead, for the reason the next section gives; what
//!   did not change is that asking for the bytes gets exactly the bytes, which is
//!   why `exec_inherits_both_child_streams_unchanged` was re-pointed at the flag
//!   rather than deleted. It is still the test that governs this design.
//!
//!   **The cost, stated rather than discovered:** stdout and stderr are separate
//!   pipes, so their *relative* interleaving is no longer guaranteed to match what
//!   a terminal would have shown. Each stream's own order is preserved. That is
//!   inherent to reading two pipes, and it is why a capture is keyed by stream
//!   rather than stored as one merged log.
//!
//!   Each pipe is drained on its own thread. Reading them in sequence would
//!   deadlock the moment a child filled the other pipe's buffer — a wrapped
//!   command that writes a lot to stderr before finishing stdout would hang
//!   forever, and it would hang only for large outputs, which is the worst
//!   possible way to find out.
//! * **The child's exit code.**
//!
//! ## The exit code is the child's, and that is an exception with a record
//!
//! Non-negotiable rule 5 and §7 declare the `0/1/2/3` table with no per-verb
//! exception, and [`crate::exit`] states that `1` and `3` are the only codes a
//! Batten *failure* produces. A passthrough cannot honour that, because the code
//! is not Batten's to choose: a child exiting `7` must be reported as `7` or the
//! wrapper has lied about what happened.
//!
//! What survives — and it is the property fail-open actually rests on — is that
//! **Batten never *invents* a `2` on this path.** A mediated call is adjudicated
//! by [`crate::hook`], never here, so nothing reads an `exec` code as a policy
//! verdict. A `2` from this verb is the child's `2`, and
//! `exec_passes_through_a_code_outside_the_table` pins the whole reading.
//!
//! Mechanically the code travels as [`Passthrough`] on the error channel, the same
//! route [`crate::Denial`] takes for the same reason — the library never exits a
//! process. That keeps [`ExitCode`] total over the four codes Batten *chooses*
//! rather than widening the table to hold one it does not.
//!
//! ## What the caller is charged for (CLOUD-429)
//!
//! The tee above and the store below are the two facts this verb sits between,
//! and for a while it did both unconditionally: the bytes were written to
//! Batten's streams *and* stored, content-addressed, so a caller paid twice —
//! once in tokens for output it did not ask for, once in ceremony for the
//! redirection that avoids them. The tell that the cost was Batten's rather than
//! the caller's is that `AGENTS.md` had to carry a redirect-to-a-file rule and a
//! guard had to enforce it. A wrapper that is token-kind foregrounded needs no
//! redirection backgrounded.
//!
//! **So the default answer is a [`Record`], and `--tee` restores the bytes.**
//! The record is pointer-only by the shape of the type rather than by a filter:
//! an exit code and one [`capture::Capture`] per stream, each a handle, a count
//! and a digest. There is no field a wrapped command's secret can travel in.
//!
//! Two axes, both **adopted** from tools this repo already pins rather than
//! invented here — [`OutputFormat`] is hk's and [`OutputStyle`] is mise's, down
//! to `style_only()`'s separation of the stream style from the suppression of
//! the tool's own metadata. A caller who knows either tool needs no second
//! vocabulary, and a name that means one thing in a pinned tool must not mean
//! another here. Crossing two axes is a product, which house-style §8 exists to
//! resist; taken deliberately because they are genuinely orthogonal, with the
//! fallback recorded on CLOUD-429 (hk's format axis alone, style fixed).
//!
//! **What this change does NOT do:** loosen `run-shape-guard`'s redirect rule.
//! That guard covers every verdict-bearing command, not `exec`, and relaxing it
//! as a side effect of making one wrapper token-kind is how a rule stops meaning
//! what it says. It gets its own change or it stays as it is.
//!
//! ## One call, N commands, and a capture you can read while it is still open
//! (CLOUD-430)
//!
//! Two requirements that turn out to be one mechanism.
//!
//! **Bundling adopts mise's `:::`** ([`BUNDLE_SEPARATOR`]) rather than inventing
//! a separator, and it needed no parser change at all: the tail is already every
//! token after `--`, so a bundle is a property of the tokens. `--jobs` is the
//! width and `--continue-on-error` the failure policy, both mise's names for
//! mise's meanings. **The bundle's code is the FIRST non-zero in declaration
//! order** — never whichever child finished last, which `--jobs` would otherwise
//! make a property of the scheduler rather than of the bundle.
//!
//! **A live capture is a spool with a committed-length watermark**
//! ([`capture::Spool`]), and that shape is forced rather than chosen: the digest
//! hashes the *complete* output, so it cannot be the key while the stream is
//! open. Readers read only as far as the watermark; the spool seals into the
//! ordinary content-addressed record at exit, byte-identical to what the same
//! command run on its own would have stored. Bundling must not change a
//! capture's identity, or every receipt keyed to one breaks.
//!
//! The lock is `fs4` rather than an in-process primitive, and the reason is the
//! failure this substrate has to survive: an OS advisory lock is released by the
//! kernel when its holder dies, so a supervisor `SIGKILL`ed mid-write (the case
//! the section below is about) leaves a reader a defined prefix instead of a lock
//! nobody can release. [`capture::Spool`] carries the full argument; the crate's
//! concurrency posture is `.claude/rules/rust.md`'s, and this line reads it
//! rather than re-deriving it (CLOUD-747).
//!
//! The threads in this module are OS threads for the same posture's reason: one
//! per pipe on the drain path, `std::thread::scope` for a `--jobs` wave, and
//! **both stay because nothing measured asks otherwise**. `--jobs` is already
//! parallel and already spawns no thread it does not need; converting working
//! parallelism into different working parallelism buys nothing without a number,
//! and no number has been produced.
//!
//! ## Whose tree is it, and who is already managing it (CLOUD-427)
//!
//! A dispatched tree outlives the dispatcher by default: a `SIGTERM` to Batten
//! kills Batten, the child is reparented to init, and nothing holds the pids.
//! Owning it means a process group — and a process group is exactly the thing a
//! *nested* manager must not make twice, because the outer `killpg` then reaches
//! the inner manager and not the leaves.
//!
//! mise already defines that protocol, and Batten interoperates with it rather
//! than reproducing it. mise's `should_use_pgroup()` declines on two observations
//! —  [`TASK_PGID_MANAGED_ENV`] present, or the process is its own session leader
//! — and Batten honours both, adding a third of its own: the
//! `[exec] manage_process_group` key, **default `false`**. The third is not
//! redundant: the first two are necessary and provably not sufficient. Measured
//! on a live session, a `mise run land` under the harness's Bash tool made its
//! own group (rule 2 asks whether *mise* leads the session, and there the Bash
//! did), so an orchestrator's intent to `kill(-pgid)` a grandchild is simply not
//! observable from the process table. What cannot be decided must be declared,
//! and it must default to today's behaviour.
//!
//! Two consequences, each load-bearing:
//!
//! * **The predicate is computed once**, at spawn, and the same value is read at
//!   teardown. mise's own cache comment names the failure when the two disagree:
//!   only the direct pid gets the signal, and the grandchildren leak.
//! * **Grouping obliges forwarding.** A new group is no longer the terminal's
//!   foreground group, so `^C` stops reaching the child — grouping without
//!   forwarding would take a signal path away and give nothing back. HUP, INT,
//!   QUIT and TERM are forwarded to the group, escalating to `SIGKILL` after
//!   [`GROUP_GRACE`] — or immediately on a **second** signal, which is what
//!   every supervisor in this class does and what Batten swallowed until
//!   CLOUD-746. The record reports `128 + the signal Batten received`, never the
//!   signal the child died of: a child that ignored TERM and fell to the
//!   escalated KILL must not read as `137` to a caller that sent `15`.
//! * **And then Batten dies of that signal** (CLOUD-746). The number in the
//!   record is a description of what happened; Batten's own death is a fact
//!   about Batten, and reporting it as an exit CODE is the wrapper describing
//!   itself with a convention meant for describing a child. A shell sets `$?`
//!   the same either way, so nothing is lost and a `waitpid` caller gains
//!   `WIFSIGNALED` — which is the difference between `for f in …; do batten
//!   exec -- …; done` being interruptible and not.
//!
//! When Batten groups it sets [`TASK_PGID_MANAGED_ENV`] on the child's
//! environment, so a nested mise stands down and the leaves stay in Batten's
//! group. Without that propagation grouping is a regression, not a feature.
//!
//! ## The drain has a deadline, because EOF is not guaranteed
//!
//! The tee threads read until EOF, and EOF arrives when the last holder of the
//! write end closes it — which is *not* the moment the child is reaped. A
//! surviving grandchild that inherited stdout holds it open forever, so the
//! joins after `child.wait()` never return: `exec` hangs with the child already
//! dead. That is a live hang today rather than a prediction, and it is why the
//! drain is bounded by [`PIPE_DRAIN_TIMEOUT`] and reports through a channel
//! rather than a bare `join()`, which has no timed form.
//!
//! Bounded, not abandoned: each tee appends into a shared buffer as it goes, so
//! a drain that times out still stores the bytes that did arrive and says how
//! many — a count, never the bytes (non-negotiable rule 4). A capture that
//! quietly did not happen is indistinguishable from a command nobody checked.
//!
//! ## What is still Batten's answer
//!
//! Exactly one thing: whether the command could be *started*. An absent program
//! is a [`UsageError`] (exit `1`), the same reading
//! [`crate::rules`]'s configured-command runner gives it — the caller named
//! something that is not there, which is a statement about the invocation.
//! Reporting that as the child's code would be worse than useless, because there
//! is no child.

use std::ffi::OsString;
use std::io::{Read, Write};
use std::path::Path;
#[expect(
    clippy::disallowed_types,
    reason = "stays: `batten exec -- <cmd>` IS the spawn — the verb's whole contract is a transparent passthrough of a caller's argv, streams and exit code (CLOUD-285)"
)]
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::capture::{self, Stream};
use crate::error::{Passthrough, UsageError};
use crate::exit::ExitCode;
use crate::outputs::{self, Hit, OutputPattern};

/// The exit code a POSIX shell reports for a process killed by a signal.
///
/// A child that died on `SIGTERM` has no exit status of its own, and
/// [`std::process::ExitStatus::code`] returns `None`. Inventing `0` there would
/// report a killed build as a success — the exact false-green this engine exists
/// to prevent — so the shell's own convention is used instead: `128 + signal`.
/// Unavailable signal numbers fall back to `128`, which is still non-zero.
#[cfg(unix)]
fn signal_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(128, |signal| 128 + signal)
}

#[cfg(not(unix))]
fn signal_code(_status: std::process::ExitStatus) -> i32 {
    128
}

/// mise's marker that an ancestor is already managing this task's process group.
///
/// Read, and — when Batten is the one managing — written onto the child's
/// environment. The name is mise's `TASK_PGID_MANAGED_ENV` verbatim: it is a
/// protocol token shared with another tool, so spelling it differently would not
/// be a rename but a silent opt-out of the protocol.
pub const TASK_PGID_MANAGED_ENV: &str = "MISE_TASK_PGID_MANAGED";

/// How long a managed group has to die on the forwarded signal before `SIGKILL`.
///
/// A grace period rather than an immediate kill, because the forwarded signal is
/// the one a well-behaved child cleans up on; escalating instantly would throw
/// away the orderly shutdown that forwarding exists to deliver.
#[cfg(unix)]
const GROUP_GRACE: Duration = Duration::from_secs(5);

/// How long the pipes have to reach EOF once the child has been reaped.
///
/// See the module docs: a surviving grandchild holding the write end means EOF
/// never arrives, so this is a deadline on a wait that otherwise has no end.
const PIPE_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// hk's format axis, adopted rather than invented.
///
/// `hk/src/structured_output.rs` already spells these three for a tool that
/// reports on child processes, and a caller who knows hk must not have to learn
/// a second vocabulary to read Batten. The names are hk's; what they range over
/// is Batten's own record.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OutputFormat {
    /// Pointer lines, one per fact.
    #[default]
    Human,
    /// One JSON document.
    Json,
    /// One JSON record per line.
    Jsonl,
}

/// mise's style axis, adopted rather than invented.
///
/// `mise/src/task/task_output.rs` spells these seven, and its `style_only()`
/// separates the stream *style* from the *suppression* of the tool's own
/// metadata — a distinction Batten needs and would otherwise have conflated into
/// one key. [`OutputStyle::style_only`] is that function, by that name.
///
/// **With one command in flight, `prefix`, `replacing` and `timed` render
/// alike.** They are still accepted, because adopting half a vocabulary is how a
/// caller learns that Batten's version of a name means something else; what
/// distinguishes them is a bundle of concurrent children, which is CLOUD-430's
/// subject and not this one's.
///
/// **`timed` emits no wall-clock field, and that is the byte-stability answer**
/// §6 demands rather than a limitation. A duration in Batten's own output would
/// make the same run print differently twice, and [`crate::capture`] already
/// refuses a timestamp for exactly that reason.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema, clap::ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum OutputStyle {
    /// Each line carries the child's program name.
    Prefix,
    /// The child's bytes, verbatim and as they arrive.
    #[default]
    Interleave,
    /// Each stream whole, in a fixed order, after the child exits.
    KeepOrder,
    /// As [`OutputStyle::Prefix`]: redrawing in place needs a terminal Batten
    /// never assumes it has.
    Replacing,
    /// As [`OutputStyle::Prefix`], minus the clock — see the type's docs.
    Timed,
    /// Batten says nothing of its own; the child still speaks.
    Quiet,
    /// Nobody speaks.
    Silent,
}

impl OutputStyle {
    /// mise's `style_only()`: the stream style with the suppression removed.
    ///
    /// `quiet` and `silent` are not stream styles — they are statements about
    /// whose output is suppressed — so asking one of them how to render a line
    /// has no answer, and the default is what mise falls back to.
    const fn style_only(self) -> Self {
        match self {
            OutputStyle::Quiet | OutputStyle::Silent => OutputStyle::Interleave,
            other => other,
        }
    }

    /// Whether Batten's own record is suppressed.
    const fn suppresses_batten(self) -> bool {
        matches!(self, OutputStyle::Quiet | OutputStyle::Silent)
    }

    /// Whether the child's own bytes are suppressed even under `--tee`.
    const fn suppresses_child(self) -> bool {
        matches!(self, OutputStyle::Silent)
    }
}

/// The `[exec]` table: how `batten exec` owns what it dispatched.
///
/// One key today, and it is an opt-in rather than a tuning knob. `false` is not
/// a conservative default chosen for taste — it is the *only* value that leaves
/// the process topology byte-for-byte what it was, which is what an existing
/// consumer's orchestrator is already built against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    /// Whether Batten may put a dispatched command in its own process group and
    /// take responsibility for tearing that group down.
    ///
    /// Declared rather than inferred, because the residual case is not
    /// observable: an orchestrator two levels up intending to `kill(-pgid)` looks
    /// exactly like one that is not. Even when this is `true`, Batten still
    /// declines whenever mise's own two rules say an ancestor is already
    /// managing — see [`GroupDecision`].
    #[serde(default)]
    pub manage_process_group: bool,
    /// Whether the child's bytes are copied onto Batten's own streams.
    ///
    /// `false` is the CLOUD-429 default and the whole point: the bytes are
    /// already stored, content-addressed and addressable, so printing them again
    /// charges the caller a second time for output the engine has. `--tee`
    /// restores the old behaviour verbatim.
    #[serde(default)]
    pub tee: bool,
    /// How Batten's own record is encoded (hk's axis).
    #[serde(default)]
    pub format: OutputFormat,
    /// How a teed child's bytes are presented, and whose output is suppressed
    /// (mise's axis).
    #[serde(default)]
    pub style: OutputStyle,
    /// How many of a `:::` bundle's commands run at once — mise's `--jobs`.
    ///
    /// `1` by default, which is stricter than mise's own default and chosen
    /// rather than inherited: a bundle's commands share one working tree, and
    /// widening concurrency a caller did not ask for is how two of them start
    /// writing the same file. Zero is read as one.
    #[serde(default = "one")]
    pub jobs: usize,
    /// Whether a bundle keeps going past a command that failed — mise's
    /// `--continue-on-error`.
    #[serde(default)]
    pub continue_on_error: bool,
}

/// The `jobs` default, as a function because `serde` needs one.
const fn one() -> usize {
    1
}

impl Default for ExecConfig {
    /// [`ExecConfig::DEFAULT`], and derived from it rather than derived by the
    /// compiler.
    ///
    /// `#[derive(Default)]` reads each field's *type* default, so `jobs` would be
    /// `0` — a width nobody can mean, and one `serde`'s own `#[serde(default)]`
    /// already disagrees with. Two defaults for one key is the drift this closes.
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl ExecConfig {
    /// The settings a caller that reads no config gets.
    ///
    /// A `const` rather than `Default::default()` at each call site so the
    /// library entry points can name it in a `&`-position without a temporary,
    /// and so "the default is off" is one object a reader can follow.
    pub const DEFAULT: Self = Self {
        manage_process_group: false,
        tee: false,
        format: OutputFormat::Human,
        style: OutputStyle::Interleave,
        jobs: 1,
        continue_on_error: false,
    };
}

/// Whether Batten manages this invocation's process group — computed **once**.
///
/// The type exists to make "once" structural rather than a comment. The spawn and
/// the teardown must read the *same* answer; two call sites to a predicate over
/// the environment could disagree (a child's own `MISE_TASK_PGID_MANAGED`, a
/// `setsid` in between) and the failure mode is silent — only the direct pid gets
/// the signal, and the grandchildren leak, which is the bug this whole issue is
/// about. So the observation happens in one constructor and travels as a value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GroupDecision(bool);

impl GroupDecision {
    /// The predicate itself, over facts a caller supplies.
    ///
    /// Separated from the observation so both branches of each rule are
    /// exercisable without a `setsid` or an environment mutation, which are
    /// process-global and therefore untestable in a threaded test harness.
    const fn decide(opt_in: bool, marker_present: bool, session_leader: bool) -> Self {
        Self(opt_in && !marker_present && !session_leader)
    }

    /// [`Self::decide`] over the live process and environment.
    #[cfg(unix)]
    fn observe(opt_in: bool) -> Self {
        Self::decide(
            opt_in,
            std::env::var_os(TASK_PGID_MANAGED_ENV).is_some(),
            is_session_leader(),
        )
    }

    /// [`Self::observe`] where there are no process groups to manage.
    ///
    /// Windows has no `setpgid`, no `killpg` and none of the four forwarded
    /// signals, so there is nothing to opt into. Answering `false` unconditionally
    /// keeps the config key readable everywhere and inert where it cannot mean
    /// anything — the alternative, a parse-time refusal, would make one
    /// `batten.toml` unusable across a consumer's own matrix.
    ///
    /// Routed through [`Self::decide`] rather than constructing the answer, so
    /// that one predicate is the only thing that ever says yes or no: a second
    /// constructor here would be a second place for the two platforms to
    /// disagree, and `cross-check` would only notice the day it did.
    #[cfg(not(unix))]
    fn observe(opt_in: bool) -> Self {
        Self::decide(opt_in, true, true)
    }

    /// Whether Batten groups and therefore owns the teardown.
    const fn groups(self) -> bool {
        self.0
    }
}

/// Whether this process leads its own session.
///
/// mise's second decline rule. A session leader is the top of a job-control
/// hierarchy, so making a group under it manages nothing an ancestor was not
/// already positioned to manage. A `getsid` that fails answers "could not look",
/// and could-not-look declines — the fail-closed direction here is *not* to
/// grab ownership on a fact nobody established.
#[cfg(unix)]
fn is_session_leader() -> bool {
    rustix::process::getsid(None).is_ok_and(|sid| sid == rustix::process::getpid())
}

/// Whether the process group led by `pgid` has no members left.
///
/// `kill(-pgid, 0)`: the standard existence probe, which reports `ESRCH` when
/// there is nothing to signal. An error other than "no such group" is answered as
/// *not empty*, because the escalation that follows a `false` is the safe
/// direction — a redundant `SIGKILL` to a group that has already gone costs
/// nothing, while skipping one over an unreadable answer leaks the tree.
#[cfg(unix)]
fn group_is_empty(pgid: rustix::process::Pid) -> bool {
    rustix::process::test_kill_process_group(pgid)
        .is_err_and(|errno| errno == rustix::io::Errno::SRCH)
}

/// Send `signal` to the process group led by `pgid`, best effort.
///
/// Best effort is the honest contract: the group may already be gone, which is
/// the outcome being asked for, and `ESRCH` on the way to exiting is not a
/// failure anyone can act on.
#[cfg(unix)]
fn signal_group(pgid: rustix::process::Pid, signal: rustix::process::Signal) {
    // `let _`, not `drop`: the result is `Copy`, so dropping it is a no-op the
    // compiler warns about rather than the discard it looks like.
    let _ = rustix::process::kill_process_group(pgid, signal);
}

/// Drain `pipe` into `sink`, accumulating everything that passed through.
///
/// The tee. Chunked rather than read-to-end-then-write so a long-running child's
/// output still appears as it is produced: buffering it all until exit would make
/// `batten exec -- cargo test` look hung.
///
/// `seen` is shared rather than returned because the caller may stop waiting
/// (see [`PIPE_DRAIN_TIMEOUT`]): a return value is only readable by a join that
/// completes, so a deadline over a returned `Vec` could only ever store nothing.
/// Appended under the lock per chunk, which is the same granularity the write to
/// `sink` already has.
fn tee<R: Read, W: Write>(
    mut pipe: R,
    mut sink: W,
    seen: &Mutex<Vec<u8>>,
    spool: &Mutex<capture::Spool>,
) -> Result<()> {
    let mut chunk = [0_u8; 8192];
    loop {
        let read = pipe.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        let bytes = chunk.get(..read).unwrap_or(&[]);
        sink.write_all(bytes)?;
        sink.flush()?;
        // Committed to the spool BEFORE the in-memory copy, because the spool is
        // the only one another process can read (CLOUD-430) — a chunk that
        // reached the caller and not the spool would be output a concurrent
        // reader can never catch up to.
        match spool.lock() {
            Ok(mut held) => held.commit(bytes)?,
            Err(_) => return Err(anyhow::anyhow!("exec: the spool was poisoned")),
        }
        match seen.lock() {
            Ok(mut held) => held.extend_from_slice(bytes),
            // A poisoned lock means the other end panicked mid-append. The bytes
            // already on `sink` are the caller's answer either way, so the tee
            // keeps teeing and the capture is what it is — dropping the stream
            // here would take output away from the caller to protect bookkeeping.
            Err(_) => return Err(anyhow::anyhow!("exec: the capture buffer was poisoned")),
        }
    }
}

/// What a tee thread reports, and where its bytes accumulate meanwhile.
struct Drain {
    /// The tee's own result, arriving when the pipe reaches EOF or errors.
    outcome: mpsc::Receiver<Result<()>>,
    /// Everything written through so far.
    seen: Arc<Mutex<Vec<u8>>>,
    /// The live capture this stream is spooling into, shared with the tee thread
    /// so a drain that times out can still be sealed by the caller.
    spool: Arc<Mutex<capture::Spool>>,
}

impl Drain {
    /// Spawn a tee of `pipe` into `sink`.
    fn spawn<R, W>(pipe: R, sink: W, spool: capture::Spool) -> Self
    where
        R: Read + Send + 'static,
        W: Write + Send + 'static,
    {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let spool = Arc::new(Mutex::new(spool));
        let (tx, outcome) = mpsc::channel();
        let buffer = Arc::clone(&seen);
        let spooling = Arc::clone(&spool);
        // Detached on purpose. A thread blocked on a pipe a grandchild holds open
        // cannot be joined, and there is nothing to join it *for*: its bytes are
        // in `seen` already, and the process is on its way out.
        drop(std::thread::spawn(move || {
            drop(tx.send(tee(pipe, sink, &buffer, &spooling)));
        }));
        Self {
            outcome,
            seen,
            spool,
        }
    }

    /// Wait for EOF against what is LEFT of one shared [`PIPE_DRAIN_TIMEOUT`],
    /// then take what arrived.
    ///
    /// Returns the bytes and whether the deadline was reached. A timeout is not
    /// an error: the child's exit code is still the caller's answer, and refusing
    /// to report it because bookkeeping ran long would turn a leaked grandchild
    /// into a failed build.
    ///
    /// # Why the budget is shared (CLOUD-1288)
    ///
    /// [`PIPE_DRAIN_TIMEOUT`] reads as "a leaked grandchild costs at most ten
    /// seconds", and `the_drain_deadline_is_long_enough_to_be_about_a_leak`
    /// asserts that floor. It cost TWENTY: the two pipes were collected one after
    /// the other, each with a fresh full deadline, so a grandchild holding both
    /// open spent the constant twice.
    ///
    /// The tee threads were never the problem and are untouched — one per pipe,
    /// started at spawn time, already concurrent, and `.claude/rules/rust.md`'s
    /// concurrency table records that row as staying. What was serial is the
    /// DEADLINE ACCOUNTING, and this is where it stops being: `started` is taken
    /// once before the first stream, so the second gets whatever the first left.
    fn collect_remaining(
        self,
        started: std::time::Instant,
        stream: Stream,
        report: &mut dyn Write,
    ) -> Result<(Vec<u8>, capture::Spool)> {
        self.collect_within(
            PIPE_DRAIN_TIMEOUT.saturating_sub(started.elapsed()),
            stream,
            report,
        )
    }

    /// [`Self::collect`] with the deadline supplied.
    ///
    /// The deadline is a parameter for one reason: a test of the bound has to
    /// reach it, and reaching a ten-second bound ten times is a suite nobody
    /// runs. Production has exactly one caller, above, and it passes the constant.
    fn collect_within(
        self,
        deadline: Duration,
        stream: Stream,
        report: &mut dyn Write,
    ) -> Result<(Vec<u8>, capture::Spool)> {
        // A NON-BLOCKING TAKE FIRST, AND IT IS NOT AN OPTIMISATION (CLOUD-1288).
        // Once the budget is shared, `deadline` can legitimately be ZERO — the
        // first stream spent it all — and `recv_timeout(Duration::ZERO)` is
        // permitted to report `Timeout` without ever examining a value that is
        // already sitting in the channel. A stderr whose tee finished cleanly
        // seconds earlier would then be reported as "did not reach EOF", which is
        // a FALSE pointer on a byte-stable channel (house-style §6), fired on
        // exactly the runs this change exists to speed up.
        //
        // So the two questions are asked separately: "has this stream already
        // finished" is `try_recv`, and only when the answer is no does the
        // remaining budget get waited on. The bytes were always safe; this is the
        // output half.
        let finished = |result: Result<()>| -> Result<bool> {
            result.with_context(|| format!("tee the wrapped command's {}", stream.as_str()))?;
            Ok(false)
        };
        let timed_out = match self.outcome.try_recv() {
            Ok(result) => finished(result)?,
            // Disconnected without a value means the tee thread died without
            // reporting — a panic. The bytes it did append are still real.
            Err(mpsc::TryRecvError::Disconnected) => false,
            Err(mpsc::TryRecvError::Empty) => match self.outcome.recv_timeout(deadline) {
                Ok(result) => finished(result)?,
                Err(mpsc::RecvTimeoutError::Disconnected) => false,
                Err(mpsc::RecvTimeoutError::Timeout) => true,
            },
        };
        let bytes = match self.seen.lock() {
            Ok(held) => held.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if timed_out {
            // Pointer-only: the stream and a count, never a byte of what was
            // captured. Said out loud rather than swallowed, because a truncated
            // capture that looks complete is the failure mode a gate reading this
            // store cannot detect for itself.
            writeln!(
                report,
                "exec: {} did not reach EOF within {:?}; captured {} byte(s) \
                 — a process still holds the pipe open",
                stream.as_str(),
                deadline,
                bytes.len()
            )?;
        }
        // The spool comes back with the bytes, because sealing is the caller's:
        // a timed-out drain leaves the tee thread alive and holding its `Arc`,
        // and reclaiming the `Spool` by value would either block on that thread
        // or race it. `try_unwrap` succeeding is the ordinary case (the tee has
        // exited); the fallback reopens the same paths, which is safe because the
        // spool's identity is its handle rather than its file descriptor.
        let spool = match Arc::try_unwrap(self.spool) {
            Ok(held) => held
                .into_inner()
                .map_err(|_| anyhow::anyhow!("exec: the spool was poisoned"))?,
            Err(shared) => match shared.lock() {
                Ok(held) => held.reopen()?,
                Err(_) => return Err(anyhow::anyhow!("exec: the spool was poisoned")),
            },
        };
        Ok((bytes, spool))
    }
}

/// Where a teed stream's bytes go, and how they are dressed on the way.
///
/// One type for all four renderings, because the alternative is a `dyn Write`
/// per style and a match at the spawn site that has to stay in step with
/// [`OutputStyle`]. `discard` is a variant rather than an `Option<Sink>` for the
/// same reason: the tee thread still has to run — the bytes are still captured —
/// so "nobody sees this" is a way of writing, not an absence of one.
struct ChildSink {
    /// Which of Batten's own streams this copies to.
    ///
    /// A [`capture::LiveStream`], not a [`Stream`]: a tee copies a child's pipe
    /// to a terminal, and `Stream::Response` names bytes no child wrote. The
    /// narrower type is what keeps the two sinks below a total choice rather
    /// than a match with an unreachable third arm.
    stream: capture::LiveStream,
    /// The per-line prefix, when the style asks for one.
    prefix: Option<String>,
    /// Whether the next byte starts a line, so a prefix lands in the right place
    /// across chunk boundaries — a pipe splits wherever it likes.
    at_line_start: bool,
    /// Whether these bytes reach a stream at all.
    discard: bool,
}

impl ChildSink {
    /// The sink `stream` gets under `settings`, for a child named `program`.
    fn of(settings: &ExecConfig, program: &str, stream: capture::LiveStream) -> Self {
        let style = settings.style;
        let showing = settings.tee && !style.suppresses_child();
        let prefix = match style.style_only() {
            // Deferred until after the exit, so nothing is written as it arrives.
            OutputStyle::KeepOrder | OutputStyle::Interleave => None,
            _ => Some(format!("{program}| ")),
        };
        ChildSink {
            stream,
            prefix,
            at_line_start: true,
            discard: !showing || style.style_only() == OutputStyle::KeepOrder,
        }
    }

    /// Write `buf` to `target`, inserting the prefix at each line start.
    fn dress<W: Write>(&mut self, target: &mut W, buf: &[u8]) -> std::io::Result<()> {
        let Some(prefix) = self.prefix.as_ref() else {
            return target.write_all(buf);
        };
        for byte in buf {
            if self.at_line_start {
                target.write_all(prefix.as_bytes())?;
                self.at_line_start = false;
            }
            target.write_all(std::slice::from_ref(byte))?;
            self.at_line_start = *byte == b'\n';
        }
        Ok(())
    }
}

impl Write for ChildSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if self.discard {
            // Reported as written, because it was: the capture has it. Returning
            // a short count here would make the tee loop spin on bytes it has
            // already accounted for.
            return Ok(buf.len());
        }
        if self.stream.is_stderr() {
            self.dress(&mut std::io::stderr(), buf)?;
        } else {
            self.dress(&mut std::io::stdout(), buf)?;
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if self.discard {
            return Ok(());
        }
        if self.stream.is_stderr() {
            std::io::stderr().flush()
        } else {
            std::io::stdout().flush()
        }
    }
}

/// One dispatched command's whole result, before anything is reported.
///
/// Carried rather than reported as it happens, for a reason `--jobs` makes
/// unavoidable: with several children in flight, the order things *finish* in is
/// a property of the machine, and Batten's output has to be a property of the
/// bundle. So every command's bytes, captures, code and deferred notices come
/// back here and are rendered in DECLARATION order.
#[derive(Debug)]
struct Outcome {
    /// Position in the bundle, zero-based, as declared.
    index: usize,
    /// The code this command reported.
    exit: i32,
    /// Everything the command wrote to stdout.
    out_bytes: Vec<u8>,
    /// Everything the command wrote to stderr.
    err_bytes: Vec<u8>,
    /// The sealed pointer per stream, stdout first.
    captures: [capture::Capture; 2],
    /// Anything the drain had to say, held back so it lands in bundle order.
    notices: Vec<u8>,
    /// The signal **Batten itself** was sent, if any (CLOUD-746 S2).
    ///
    /// Carried rather than acted on here, because the re-raise must happen after
    /// the record is emitted and every capture is sealed — and in a bundle that
    /// is a decision about the whole bundle rather than about one command.
    ///
    /// Read on unix only, because only unix has signals: the non-unix
    /// [`Forwarding`] stub always answers `None` and the re-raise is
    /// `#[cfg(unix)]`, so nothing there can read this. Declared dead with
    /// `expect` rather than `allow`, so the day a Windows path grows a reason to
    /// read it the annotation goes red instead of quietly staying true.
    #[cfg_attr(
        not(unix),
        expect(
            dead_code,
            reason = "windows has no signals: the `Forwarding` stub always answers None and the re-raise is cfg(unix), so nothing reads this there"
        )
    )]
    received: Option<i32>,
}

/// One command's line in the record: pointers, and nothing that is not a pointer.
#[derive(Debug, Serialize)]
struct CommandRecord<'a> {
    /// Position in the bundle, zero-based.
    index: usize,
    /// The code this command reported.
    exit: i32,
    /// One pointer per stream, in a fixed order.
    captures: &'a [capture::Capture],
}

/// What `exec` says about a run whose bytes it did not print.
///
/// Every field is a fact **about** the output and none of them is the output: an
/// exit code, and one [`capture::Capture`] per stream — a handle, a byte count
/// and a digest. Pointer-only then holds by the shape of the type rather than by
/// a filter that has to be right every time, which is the stronger claim
/// non-negotiable rule 4 actually wants.
///
/// **No tail, and that is a decision rather than an omission.** CLOUD-429's
/// acceptance offers "a bounded tail", and the same issue's own reading of
/// Sentry's attachment model rejects the trade it implies: pointer-only must
/// stay structural, "not become `pointer-only except when the payload is short
/// enough to be tempting`". `tests/pointer_only.rs` classifies this verb on
/// exactly that question — whether Batten's report adds a copy of the child's
/// bytes — so a preview would be the one thing the census is watching for. The
/// routes to the bytes are `--tee` and the capture the handle addresses.
///
/// **A one-command bundle renders exactly as a bare command always did**
/// (CLOUD-430). Every receipt and every reader keyed to those lines predates
/// bundling, so a per-command index that appeared unconditionally would be a
/// byte-stability break dressed as a feature.
#[derive(Debug, Serialize)]
struct Record<'a> {
    /// The verb, so one line of `jsonl` is self-describing among others.
    verb: &'static str,
    /// The code the caller is about to receive — the bundle's, not a child's.
    exit: i32,
    /// How many commands the bundle DECLARED, which is not how many ran.
    declared: usize,
    /// One entry per command that ran, in declaration order.
    commands: Vec<CommandRecord<'a>>,
}

impl Record<'_> {
    /// Render into `report` in `format`.
    ///
    /// Byte-stable across every format/style pair (§6): nothing here is a clock,
    /// a duration, a path or a map iteration order.
    fn emit(&self, format: OutputFormat, report: &mut dyn Write) -> Result<()> {
        // The index is written only for a real bundle. See the type's docs: a
        // bare command's lines are a published shape.
        let bundled = self.declared > 1;
        match format {
            OutputFormat::Human => {
                for command in &self.commands {
                    let tag = if bundled {
                        format!("[{}] ", command.index)
                    } else {
                        String::new()
                    };
                    if bundled {
                        writeln!(report, "exec: {tag}exit {}", command.exit)?;
                    }
                    for capture in command.captures {
                        writeln!(
                            report,
                            "exec: {tag}{} {} byte(s) {}",
                            capture.stream,
                            capture.bytes,
                            capture.handle()
                        )?;
                    }
                }
                if bundled && self.commands.len() < self.declared {
                    // Said out loud rather than left to be inferred from a short
                    // list: a bundle that stopped early and one that ran clean
                    // must not look alike.
                    writeln!(
                        report,
                        "exec: {} of {} command(s) ran",
                        self.commands.len(),
                        self.declared
                    )?;
                }
                writeln!(report, "exec: exit {}", self.exit)?;
            }
            OutputFormat::Json => {
                writeln!(report, "{}", serde_json::to_string_pretty(self)?)?;
            }
            OutputFormat::Jsonl => {
                // One record per line, hk's shape. The exit first, because a
                // reader tailing the stream wants the verdict before the detail.
                writeln!(
                    report,
                    "{}",
                    serde_json::to_string(&serde_json::json!({
                        "verb": self.verb,
                        "record": "exit",
                        "exit": self.exit,
                        "declared": self.declared,
                        "ran": self.commands.len(),
                    }))?
                )?;
                for command in &self.commands {
                    for capture in command.captures {
                        writeln!(
                            report,
                            "{}",
                            serde_json::to_string(&serde_json::json!({
                                "verb": self.verb,
                                "record": "capture",
                                "index": command.index,
                                "exit": command.exit,
                                "stream": capture.stream,
                                "bytes": capture.bytes,
                                "digest": capture.digest,
                            }))?
                        )?;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Put `builder`'s child in its own process group, when `decision` says so.
///
/// Two halves, and the second is what makes the first safe to do at all: the
/// group, and the marker that tells a nested mise an ancestor is already managing
/// one. Grouping without propagating would leave mise making a second group under
/// Batten's, so Batten's `killpg` would reach mise and not the leaves — strictly
/// worse than not grouping, which is why they are one function.
///
/// `CommandExt::process_group` rather than mise's `pre_exec(setpgid)`: the
/// workspace forbids `unsafe`, and for this purpose the two are the same call.
#[cfg(unix)]
#[expect(
    clippy::disallowed_types,
    reason = "stays with the spawn it configures: the pgroup handshake is negotiated against mise's supervisor and is a property of the builder, not of a library call (CLOUD-427)"
)]
fn group_at_spawn(builder: &mut Command, decision: GroupDecision) {
    use std::os::unix::process::CommandExt as _;

    if decision.groups() {
        builder.process_group(0).env(TASK_PGID_MANAGED_ENV, "1");
    }
}

/// [`group_at_spawn`] where there are no process groups.
#[cfg(not(unix))]
#[expect(
    clippy::disallowed_types,
    reason = "stays with the spawn it configures: the no-op twin of the unix arm above, and it must carry the same verdict or a Windows clippy run reports an unannotated site (CLOUD-427)"
)]
fn group_at_spawn(_builder: &mut Command, _decision: GroupDecision) {}

/// The on-disk note that a group is currently owned, and by which Batten.
///
/// Written **before** the wait and removed on a clean reap, so its presence means
/// "a Batten died holding a group". That asymmetry is the whole design: `SIGKILL`
/// cannot be caught, so the one case forwarding cannot help with is the one case
/// a record can — this is recordable, never preventable, and a clean run leaves
/// nothing behind to read.
///
/// Out of tree, under [`crate::state::repo_state_dir`], for the reason every
/// other piece of state is: a checkout stays clean and the record survives a
/// reclone. Pointer-only by nature — a pgid and nothing else.
struct GroupRecord {
    /// `None` when Batten is not managing a group, so there is nothing to clear.
    path: Option<std::path::PathBuf>,
}

impl GroupRecord {
    /// Note that `pgid` is owned, if `decision` says Batten owns it.
    ///
    /// # Errors
    ///
    /// Returns an error when the note cannot be written. Not a silent skip: a
    /// caller that asked Batten to own the tree has been told the leak is
    /// recoverable, and an unwritable record makes that untrue without saying so.
    fn write(repo_root: &Path, decision: GroupDecision, pgid: u32) -> Result<Self> {
        if !decision.groups() {
            return Ok(Self { path: None });
        }
        let dir = crate::state::repo_state_dir(repo_root)?.join("exec");
        std::fs::create_dir_all(&dir).context("create the exec group-record directory")?;
        // Keyed by Batten's OWN pid, not the group's: the reader's question is
        // "which supervisor died", and a second `exec` in the same checkout must
        // not overwrite the first one's note.
        let path = dir.join(format!("group.{}", std::process::id()));
        std::fs::write(&path, format!("{pgid}\n")).context("record the owned process group")?;
        Ok(Self { path: Some(path) })
    }

    /// Remove the note, because the child was reaped and the group is gone.
    fn clear(self) {
        if let Some(path) = self.path {
            // A record that cannot be removed is stale rather than harmful — it
            // names a pgid that no longer exists, and a reader must tolerate that
            // anyway, since a pid can be reused between the write and the read.
            drop(std::fs::remove_file(path));
        }
    }
}

/// The signals Batten forwards to a group it owns.
///
/// The four job-control signals a caller sends *on purpose*. Deliberately not
/// `SIGKILL` (uncatchable, so a `kill -9` to Batten is recordable at best and
/// never preventable) and not `SIGUSR1`/`SIGUSR2`, which mean whatever a
/// consumer's own tooling has agreed they mean.
#[cfg(unix)]
const FORWARDED: &[i32] = &[
    signal_hook::consts::SIGHUP,
    signal_hook::consts::SIGINT,
    signal_hook::consts::SIGQUIT,
    signal_hook::consts::SIGTERM,
];

/// Signal forwarding for the lifetime of one managed child.
///
/// Absent — every field `None` — whenever [`GroupDecision::groups`] is false, so
/// an invocation with the opt-in off installs no disposition at all and the
/// process topology is byte-for-byte what it was before CLOUD-427.
#[cfg(unix)]
struct Forwarding {
    /// `None` when Batten is not managing this child's group.
    active: Option<ForwardingThread>,
}

/// The pieces of a live forwarder.
#[cfg(unix)]
struct ForwardingThread {
    /// Ends the `Signals` iterator, which is how the worker is asked to stop.
    handle: signal_hook::iterator::Handle,
    /// The worker itself.
    worker: std::thread::JoinHandle<()>,
    /// The signal Batten was sent, or `0` for none. Read once, after the join.
    received: Arc<std::sync::atomic::AtomicI32>,
    /// The group to forward to, published by [`Forwarding::adopt`] once the
    /// child exists. `0` until then.
    ///
    /// This slot is what lets the registry be installed BEFORE the spawn
    /// (CLOUD-746 S3). The worker can be parked on the signal stream while the
    /// group it will forward to does not exist yet, which is the whole point:
    /// the alternative orders the two the other way and leaves a window in
    /// which the child is a group leader and Batten still holds the default
    /// dispositions.
    pgid: Arc<std::sync::atomic::AtomicI32>,
}

/// How long the worker waits for a pgid after taking a signal.
///
/// Only reachable when a signal lands in the window between arming and the
/// spawn, which is the case CLOUD-746 S3 exists for: the child is about to
/// exist, so waiting a moment for it is what makes the signal reach it instead
/// of racing past it. A spawn that never happens ends the wait at this bound and
/// the signal is simply recorded — there is no group to forward to.
#[cfg(unix)]
const ADOPT_GRACE: Duration = Duration::from_secs(2);

/// Wait for [`Forwarding::adopt`] to publish a group, bounded by [`ADOPT_GRACE`].
///
/// `None` when no group ever arrived, which means the spawn failed or never
/// happened — there is nothing to forward to and the signal stays recorded.
#[cfg(unix)]
fn await_group(slot: &Arc<std::sync::atomic::AtomicI32>) -> Option<rustix::process::Pid> {
    use std::sync::atomic::Ordering;

    let deadline = std::time::Instant::now() + ADOPT_GRACE;
    loop {
        let raw = slot.load(Ordering::SeqCst);
        if raw != 0 {
            return rustix::process::Pid::from_raw(raw);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of the poll this loop is: it exits the moment `adopt` publishes \
                      a group, and its outer bound is `ADOPT_GRACE`, past which it gives up rather \
                      than waits longer (CLOUD-1177)"
        )]
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(unix)]
impl Forwarding {
    /// Install the registry **before** the spawn, if `decision` says Batten owns
    /// the group.
    ///
    /// **Before, and that ordering is the fix rather than a detail** (CLOUD-746
    /// S3). Arming after the spawn leaves a window — two `Drain::spawn` calls
    /// and two `Spool::open` calls, so file IO rather than a couple of
    /// instructions — in which the child already exists as a group leader and
    /// Batten still holds the DEFAULT dispositions. A `SIGTERM` landing there
    /// kills Batten instantly and orphans the group, which is the exact leak
    /// CLOUD-427 was filed to close, reachable through a window its own fix
    /// opened.
    ///
    /// **Not by blocking the signals across the spawn instead.** A signal mask
    /// survives `exec`, so the child would inherit blocked HUP/INT/QUIT/TERM and
    /// become unkillable by exactly the signals this forwarder delivers.
    /// Resetting it in the child needs `pre_exec`, which `unsafe_code =
    /// "forbid"` puts out of reach. Install-before-spawn is the only option
    /// rather than the preferred one.
    ///
    /// # Errors
    ///
    /// Returns an error when the signal registry cannot be installed. That is an
    /// internal error rather than a silent downgrade to unmanaged: a caller that
    /// asked Batten to own the tree and got an unowned one would find out by
    /// leaking processes, which is exactly the state this issue exists to end.
    fn arm(decision: GroupDecision) -> Result<Self> {
        use std::sync::atomic::{AtomicI32, Ordering};

        if !decision.groups() {
            return Ok(Self { active: None });
        }

        let mut signals = signal_hook::iterator::Signals::new(FORWARDED)
            .context("install the signal forwarder for the wrapped command")?;
        let handle = signals.handle();
        let received = Arc::new(AtomicI32::new(0));
        let pgid = Arc::new(AtomicI32::new(0));

        let seen = Arc::clone(&received);
        let group = Arc::clone(&pgid);
        let worker = std::thread::spawn(move || {
            let first = {
                let mut stream = signals.forever();
                let Some(signal) = stream.next() else {
                    // The handle was closed: the child was reaped without Batten
                    // being signalled at all, which is every clean run.
                    return;
                };
                signal
            };
            seen.store(first, Ordering::SeqCst);

            // The signal may have arrived before the spawn published a group.
            // Wait for one rather than dropping the signal on the floor, since
            // that window is precisely what arming early exists to cover.
            let Some(pgid) = await_group(&group) else {
                return;
            };
            if let Some(sig) = rustix::process::Signal::from_named_raw(first) {
                signal_group(pgid, sig);
            }
            // Escalate on the GROUP being empty, never on Batten's direct child
            // being reaped. The two come apart routinely and the difference is
            // the whole issue: a non-interactive shell sets a background job's
            // INT and QUIT to ignored, so `sh -c 'sleep 300 & wait'` dies on the
            // forwarded INT while the `sleep` it started does not. Waiting on the
            // child there would report a clean teardown over a live orphan.
            //
            // Polled rather than slept through, so a group that dies promptly —
            // the common case — costs one poll interval and not the whole grace.
            let deadline = std::time::Instant::now() + GROUP_GRACE;
            while std::time::Instant::now() < deadline {
                if group_is_empty(pgid) {
                    return;
                }
                // A SECOND SIGNAL ESCALATES (CLOUD-746 S1), and the stream is
                // read rather than left to queue. `Signals::new` has already
                // replaced the default disposition for all four, so a worker
                // that stops reading does not merely miss the second Ctrl-C —
                // it SWALLOWS it, and for the whole grace the only thing that
                // still gets out is `SIGKILL`. That is a regression against
                // having no handler at all, and it is what trains an operator
                // to reach for `kill -9`.
                //
                // `pending` rather than a second blocking read: this loop also
                // has a deadline and an empty-group exit to honour, and parking
                // on the stream would abandon both.
                if signals.pending().next().is_some() {
                    signal_group(pgid, rustix::process::Signal::KILL);
                    return;
                }
                #[expect(
                    clippy::disallowed_methods,
                    reason = "the interval of the poll the comment above describes: the loop exits \
                              on `group_is_empty` and its outer bound is `GROUP_GRACE`, past which \
                              it escalates rather than waits longer (CLOUD-1177)"
                )]
                std::thread::sleep(Duration::from_millis(20));
            }
            signal_group(pgid, rustix::process::Signal::KILL);
        });

        Ok(Self {
            active: Some(ForwardingThread {
                handle,
                worker,
                received,
                pgid,
            }),
        })
    }

    /// Publish the group the armed forwarder should forward to.
    ///
    /// `child_pid` **is** the group id: `process_group(0)` makes the child a
    /// group leader, so the two are the same number by construction rather than
    /// by a lookup that could race the child's death.
    ///
    /// # Errors
    ///
    /// Returns an error when the child's pid is not a usable group id — the same
    /// refuse-rather-than-downgrade posture arming has, and for the same reason.
    fn adopt(&self, child_pid: u32) -> Result<()> {
        use std::sync::atomic::Ordering;

        let Some(active) = self.active.as_ref() else {
            return Ok(());
        };
        let Some(pgid) = i32::try_from(child_pid)
            .ok()
            .filter(|pgid| rustix::process::Pid::from_raw(*pgid).is_some())
        else {
            return Err(anyhow::anyhow!(
                "exec: the spawned child reported an unusable pid, so its group cannot be owned"
            ));
        };
        active.pgid.store(pgid, Ordering::SeqCst);
        Ok(())
    }

    /// Stop forwarding and report the signal Batten was sent, if any.
    ///
    /// Called immediately after the child is reaped. Closing the handle is what
    /// ends a worker parked on the signal stream, and the join is what orders the
    /// escalation before Batten's own exit — a supervisor that reported the
    /// teardown and then left it half-done would be the bug wearing the fix's
    /// clothes.
    fn finish(self) -> Option<i32> {
        use std::sync::atomic::Ordering;

        let active = self.active?;
        active.handle.close();
        // A worker that panicked has still recorded what it saw before it could,
        // and a panic on the way out is not worth failing a completed command for.
        drop(active.worker.join());
        match active.received.load(Ordering::SeqCst) {
            0 => None,
            signal => Some(signal),
        }
    }
}

/// [`Forwarding`] where there are no signals to forward.
#[cfg(not(unix))]
struct Forwarding;

#[cfg(not(unix))]
impl Forwarding {
    /// Always inactive: [`GroupDecision::observe`] never groups here.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "one signature across both platforms; the unix half genuinely fails"
    )]
    fn arm(_decision: GroupDecision) -> Result<Self> {
        Ok(Self)
    }

    /// Nothing to adopt: there is no group and no registry.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "one signature across both platforms; the unix half genuinely fails"
    )]
    fn adopt(&self, _child_pid: u32) -> Result<()> {
        Ok(())
    }

    /// Nothing was forwarded, so nothing outranks the child's own status.
    const fn finish(self) -> Option<i32> {
        None
    }
}

/// Run `command`, teeing its streams, and report its exit code unchanged.
///
/// Returns [`ExitCode::Success`] only for a child that exited `0`; every other
/// code travels as a [`Passthrough`] error, which the binary boundary turns into
/// that exact status.
///
/// # Errors
///
/// Returns a [`UsageError`] when `command` is empty or names a program that
/// cannot be started, and a [`Passthrough`] for any non-zero child code. A store
/// that cannot be written is an internal error, never a silent skip: this is the
/// substrate a gate reads, and a capture that quietly did not happen is
/// indistinguishable from a command nobody checked. Nothing here returns
/// [`ExitCode::Violation`] of its own accord; a `2` from this verb came from the
/// child.
pub fn run(command: &[String]) -> Result<ExitCode> {
    run_with(command, &[], &ExecConfig::DEFAULT, &mut std::io::sink())
}

/// [`run`], with the output predicates to apply and where to report a hit.
///
/// # Errors
///
/// As [`run`].
pub fn run_with(
    command: &[String],
    patterns: &[OutputPattern],
    settings: &ExecConfig,
    report: &mut dyn Write,
) -> Result<ExitCode> {
    // The repository root, not the cwd: `state::derive_repo_name` needs a real
    // final path component, and `.` has none — measured, as
    // `cannot derive a repository name from .`. Resolving through `git::repo_root`
    // also means a capture taken from a subdirectory lands in the same store as one
    // taken from the top, which is what makes a handle portable within a checkout.
    let root = crate::git::repo_root(Path::new("."))?;
    run_in_with(&root, command, patterns, settings, report)
}

/// [`run`], with the repository root the capture is stored under.
///
/// # Errors
///
/// As [`run`].
pub fn run_in(repo_root: &Path, command: &[String]) -> Result<ExitCode> {
    run_in_env(repo_root, command, &[])
}

/// [`run_in`], with variables published into the child's environment.
///
/// **A PARAMETER RATHER THAN `std::env::set_var`, and the workspace forbids the
/// alternative outright.** Setting a variable on this process would be `unsafe`,
/// would outlive the call, and would reach every later child whether or not the
/// fact is still true — a bet unwound two laps ago would still be published.
///
/// It is also not an [`ExecConfig`] field: that struct is deserialized from
/// committed configuration, and these pairs are resolved per call from the state
/// of the run. A consumer must not be able to declare one.
///
/// # Errors
///
/// As [`run`].
pub fn run_in_env(
    repo_root: &Path,
    command: &[String],
    published: &[(String, String)],
) -> Result<ExitCode> {
    run_in_with_env(
        repo_root,
        command,
        &[],
        &ExecConfig::DEFAULT,
        published,
        &mut std::io::sink(),
    )
}

/// [`run_in`], with the output predicates to apply and where to report a hit.
///
/// # Errors
///
/// As [`run`].
pub fn run_in_with(
    repo_root: &Path,
    command: &[String],
    patterns: &[OutputPattern],
    settings: &ExecConfig,
    report: &mut dyn Write,
) -> Result<ExitCode> {
    run_in_with_env(repo_root, command, patterns, settings, &[], report)
}

/// [`run_in_with`], with variables published into the child's environment.
///
/// # Errors
///
/// As [`run`].
pub fn run_in_with_env(
    repo_root: &Path,
    command: &[String],
    patterns: &[OutputPattern],
    settings: &ExecConfig,
    published: &[(String, String)],
    report: &mut dyn Write,
) -> Result<ExitCode> {
    let bundle = split_bundle(command)?;
    let outcomes = dispatch(repo_root, &bundle, settings, published, next_run())?;
    report_bundle(&bundle, &outcomes, patterns, settings, report)
}

/// Run a command and report WHICH declared patterns its output matched,
/// whatever it exited.
///
/// # This asks a different question from [`run_in_with_env`], and the difference
/// is the exit code
///
/// [`report_bundle`] scans for patterns only on a `0`, and says so in as many
/// words: *"Only `0` is promotable, and only a declared pattern promotes it."*
/// That is right for CLOUD-117, whose question is **is this green run lying** —
/// a child that already failed needs no promotion, and re-deciding a failure
/// Batten did not diagnose would make the wrapper's verdict unreadable.
///
/// The question here is the other one: **a run already failed, and what KIND of
/// failure was it.** CLOUD-861 is the measured case — a `verify` that died on a
/// full disk is not a defect in the tree, and reporting it as one sends an
/// author to reproduce a condition their branch did not create. Reusing the
/// promotion path could not answer it, because the promotion path returns before
/// it scans.
///
/// So this is a sibling rather than a flag on that one: one function answering
/// both questions would have to decide, per caller, whether a hit means *promote
/// this success* or *explain this failure*, and those produce opposite verdicts
/// from identical inputs.
///
/// # It returns hits, never bytes
///
/// [`Hit`] is `stream:line id` and carries no matched text, so a caller learns
/// which class of failure it was without the output passing through its hands —
/// non-negotiable rule 4 held in the return TYPE rather than by each caller
/// remembering. A wrapped command's output is the likeliest place in this whole
/// engine for a secret to appear, which is what makes that load-bearing here.
///
/// The exit code is returned rather than raised: a gate that ran and refused is
/// an ANSWER to its caller, and wrapping it in [`Passthrough`] would make the
/// caller unwrap an error to read a verdict it asked for.
///
/// # Errors
///
/// A malformed bundle, or a boundary that could not start the child. A child
/// that ran and failed is `Ok`, with its code.
pub(crate) fn classify_in_env(
    repo_root: &Path,
    command: &[String],
    patterns: &[OutputPattern],
    settings: &ExecConfig,
    published: &[(String, String)],
) -> Result<(i32, Vec<Hit>)> {
    let bundle = split_bundle(command)?;
    let outcomes = dispatch(repo_root, &bundle, settings, published, next_run())?;
    let code = bundle_code(&outcomes);
    let mut found: Vec<Hit> = Vec::new();
    for outcome in &outcomes {
        found.extend(outputs::hits(patterns, Stream::Stdout, &outcome.out_bytes));
        found.extend(outputs::hits(patterns, Stream::Stderr, &outcome.err_bytes));
    }
    Ok((code, found))
}

/// A bundle's exit code: the FIRST non-zero in declaration order.
///
/// Extracted rather than written twice (CLOUD-430). A bundle where command 2 of
/// 3 failed and command 3 succeeded must not report `0`; and reading the FIRST
/// failure rather than the last keeps the answer a property of the bundle rather
/// than of the scheduler, which `--jobs` would otherwise make non-deterministic.
/// Two spellings of that reduction is two authorities over one number.
fn bundle_code(outcomes: &[Outcome]) -> i32 {
    outcomes
        .iter()
        .map(|outcome| outcome.exit)
        .find(|exit| *exit != 0)
        .unwrap_or(0)
}

/// Run a program at `root/<program>` with `stdin` piped in, and read back its
/// exit code and stdout.
///
/// **The cheap sibling of [`run_in`], and it lives here because `exec` is the
/// placed child-process adapter** (`policy/spawn-adapters.rego`). Two callers
/// needed exactly this — the end-of-turn nudge invoking the programs the retired
/// `stop-guard.sh` invoked, and a `[[recorder]]` row running the gate whose
/// verdict it records — and each had grown its own `Command::new`, which is two
/// spawns in two unplaced modules and one shape written twice.
///
/// It is deliberately NOT `run_in`: no tee, no capture spool, no process group,
/// no signal forwarding, no report. Those exist because `exec` is a supervisor
/// for a command a human named; this runs a program the committed config named,
/// wants its stdout as a value, and must stay cheap enough for the mediated path.
///
/// **stderr is discarded, deliberately.** Every program reached this way is a
/// gate whose stderr is its own pointer report, and a caller that surfaced it
/// would be a second, unasked-for channel for another rule's findings.
///
/// `None` is could-not-look, collapsed on purpose: absent, unrunnable, a broken
/// pipe and a child that died without a code are all "no answer", and no caller
/// can act differently on which. A caller that needs clean-versus-unreadable
/// apart must not infer it from here.
pub(crate) fn piped(
    root: &Path,
    program: &Path,
    args: &[String],
    stdin: &str,
) -> Option<(i32, String)> {
    let path = root.join(program);
    if !path.is_file() {
        return None;
    }
    // `None` for the resolve root: the program is already absolute here, so a
    // relative name cannot arise and handing a directory would only be a guess at
    // one.
    // `Drop`: both callers of this entry point parse the string it returns.
    piped_through(root, None, path.to_str()?, args, stdin, Diagnostics::Drop)
}

/// The one spawn both piped entry points share.
///
/// **Extracted rather than duplicated, and the reason is the gate this branch
/// owes** (CLOUD-1338). [`piped_argv`] was written with its own `Command::new`
/// and its own `#[expect(clippy::disallowed_types)]`, which is the inventory
/// growing by one for a body byte-identical to this one — an annotation is meant
/// to record a spawn somebody decided on, not to be the cheap way past the lint.
/// `policy/spawn-widening.rego` refuses an added escape now, and this is what
/// that refusal asks for: one site, two callers.
///
/// The two callers differ in exactly one thing and it is the argument they pass:
/// how the first word RESOLVES. See [`piped_argv`]'s header for why that
/// difference may not be folded away.
///
/// THROUGH THE RESOLUTION LADDER, never `Command::new` directly, and Windows CI
/// is what said so: a `#!/usr/bin/env bash` program has no extension and no
/// executable image, so `CreateProcess` refuses it and the caller read the
/// refusal as could-not-look — a recorder column that said `-` where it should
/// have said `ready`. `spawn_resolving`'s third rung reads the shebang and runs
/// the interpreter.
#[expect(
    clippy::disallowed_types,
    reason = "stays: this is the placed adapter's ONE spawn, shared by both piped entry points so \
              the inventory does not grow per calling shape (CLOUD-1051, CLOUD-1338)"
)]
fn piped_through(
    root: &Path,
    resolve_root: Option<&Path>,
    program: &str,
    args: &[String],
    stdin: &str,
    diagnostics: Diagnostics,
) -> Option<(i32, String)> {
    let mut child = crate::rules::spawn_resolving(resolve_root, program, |resolved, extra| {
        Command::new(OsString::from(resolved))
            .args(extra.iter().map(OsString::from))
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(diagnostics.redirection())
            .spawn()
    })
    .ok()?;
    // TAKEN AND DROPPED EVEN WHEN EMPTY, because a gate that reads stdin blocks
    // until it closes. A caller with nothing to say still has to say nothing and
    // hang up, which is what an owned handle going out of scope here does.
    {
        // **A GATE THAT DID NOT READ STDIN STILL ANSWERED** (review of #848). This
        // was `.ok()?`, which turns an ordinary `EPIPE` into `None` — and `None`
        // reaches `land::ready` as `Readied::Unrunnable`, a could-not-look, over a
        // gate that ran and produced a real verdict. Rust ignores `SIGPIPE`, so a
        // gate that ignores its stdin and exits before the write completes is not
        // a crash; it is a program that had already decided.
        //
        // The early `?` also abandoned a live child without waiting, leaking a
        // zombie per occurrence. Dropping the handle closes the pipe either way,
        // and `wait_with_output` below is what actually decides.
        //
        // **ON A THREAD, because `Diagnostics::Keep` made a blocking write here a
        // DEADLOCK** (review of #848). Nothing drains stdout or stderr until
        // `wait_with_output` below, and this write completes first — so with
        // stderr piped, a gate that emits more than one pipe buffer (~64 KiB) of
        // diagnostics before consuming all of stdin blocks writing stderr while
        // this blocks writing stdin, and the lap hangs with no timeout. With
        // `Stdio::null()` that was unreachable: the child could only ever block on
        // stdout, which the caller was not filling. `land::ready` feeds a pull
        // request BODY on stdin to a gate that takes `Keep`, which is exactly the
        // shape.
        //
        // Detached rather than joined: the handle closes when the thread's owned
        // pipe drops, and `wait_with_output` is what decides. A caller must never
        // wait on the writer, because a gate that ignores its stdin is the case
        // above that legitimately never drains it.
        if let Some(mut pipe) = child.stdin.take() {
            let body = stdin.to_owned();
            drop(std::thread::spawn(move || {
                let _ = pipe.write_all(body.as_bytes());
            }));
        }
    }
    let finished = child.wait_with_output().ok()?;
    let mut output = String::from_utf8_lossy(&finished.stdout).into_owned();
    if diagnostics == Diagnostics::Keep {
        // STDOUT FIRST, because that is where a verdict is written and a caller
        // parsing one must not skip a diagnostic to find it.
        let reason = String::from_utf8_lossy(&finished.stderr);
        if !reason.trim().is_empty() {
            if !output.is_empty() && !output.ends_with('\n') {
                output.push('\n');
            }
            output.push_str(reason.trim_end());
        }
    }
    Some((finished.status.code()?, output))
}

/// Whether a spawn's stderr joins its stdout, and it is per CALL SITE.
///
/// **A shared spawn may not decide this, which is what the first attempt got
/// wrong** (review of #848). Capturing everywhere fixed `land::ready`'s empty
/// `detail` and broke two callers that PARSE the string it returns:
/// `review::ready` runs `serde_json::from_str` over it, so a runner emitting any
/// diagnostic — a deprecation warning, a TLS notice — would fail to parse and
/// read as *never dispatched*, which is the one arm a predicate over
/// `input.tree.review` may refuse on; and `recorder::run_program`'s own doc
/// states the contract verbatim, *"stderr is discarded, deliberately … a
/// recorder that surfaced another gate's findings would be a second, unasked-for
/// channel for them"*, so a gate writing `path:line` to stderr would have written
/// it into a recorded column.
///
/// So the question is the caller's: a gate whose REASON is the payload keeps it,
/// and a program whose stdout is a parsed value does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Diagnostics {
    /// Discard stderr. For a caller that parses the returned string.
    Drop,
    /// Fold stderr in after stdout. For a caller reporting a gate's own reason.
    Keep,
}

impl Diagnostics {
    fn redirection(self) -> Stdio {
        match self {
            Self::Drop => Stdio::null(),
            Self::Keep => Stdio::piped(),
        }
    }
}

/// [`piped`] over an ARGV rather than a program path.
///
/// # Why a sibling rather than a widened `piped`
///
/// The two resolve differently and the difference is not cosmetic. [`piped`]
/// takes a program AT A PATH — `root.join(program)`, guarded by `is_file`, with
/// no resolve root because the result is already absolute. This takes a command
/// whose first word is a NAME the ladder resolves on `PATH`, which is what a task
/// runner's invocation is. Folding them would give one function whose first
/// argument means two things depending on whether it happens to exist as a file,
/// and the guard that makes `piped` safe is exactly wrong here: a task name is
/// not a file, so `is_file` would answer could-not-look for every one of them —
/// a gate that reads as unreachable rather than as refusing, which is the dead
/// class this engine exists to refuse.
///
/// # Why it exists
///
/// The landing lap's ready phase runs gates that take the pull request's BODY on
/// stdin, and nothing here could spell that shape: [`run_in`] has no stdin
/// channel and [`piped`] has no argv. The alternative was a fifth `Command::new`
/// in whichever module needed it, which is the second-spawn-in-an-unplaced-module
/// shape `piped`'s own header records being added to remove.
///
/// **It never spells an argv.** Both the runner and the task names arrive from
/// the consumer's own configuration, because a task name inside `crates/batten`
/// is non-negotiable rule 1's plainest violation.
///
/// `None` is could-not-look, collapsed for [`piped`]'s reason: unresolvable, a
/// broken pipe, and a child that died without a code are all "no answer", and no
/// caller can act differently on which.
///
/// # [`Diagnostics`] IS THE CALLER'S, and hardcoding it here was the same defect
/// one layer up
///
/// This entry point pinned [`Diagnostics::Keep`] because the LANDING GATES need
/// their refusal reason: their verdict is the exit code and the coordinate is on
/// stderr, so dropping it left `Readied::Refused { detail }` empty and the
/// operator reading a refusal with nowhere to look.
///
/// **But the same entry point also fetches the pull request's BODY** (review of
/// #848), and there the returned string is PARSED rather than shown. A forge
/// client's notice on stderr — an auth warning, a deprecation, a proxy line —
/// was folded into the body, which defeats `land::ready`'s empty-body pass and
/// runs the body gates over text nobody wrote. [`Diagnostics`]' own doc forbids
/// `Keep` for a caller that parses.
///
/// That is [`piped`]'s history repeated: one shared spawn changed to fix one
/// caller's symptom, breaking the callers that read the stream. The answer is the
/// same both times — the call site says which it wants.
pub(crate) fn piped_argv(
    root: &Path,
    argv: &[String],
    stdin: &str,
    diagnostics: Diagnostics,
) -> Option<(i32, String)> {
    let (program, operands) = argv.split_first()?;
    // `Some(root)`, where [`piped`] passes `None`: the first word here is a NAME
    // the ladder resolves, so rung 3 needs a directory to read a shebang out of.
    // That one argument IS the difference between the two entry points, which is
    // why they share [`piped_through`] and not a signature.
    piped_through(root, Some(root), program, operands, stdin, diagnostics)
}

/// This process's next dispatch number, for the live-capture key.
///
/// The key has to name a *run*, not just a command: through the CLI there is
/// exactly one dispatch per process and the pid would be enough, but a library
/// caller running two bundles at once — or a test binary running several cases in
/// parallel — would otherwise give both the same spool. Starting at zero keeps
/// the CLI's handle derivable by the caller that spawned it, which is what makes
/// a live capture addressable at all without printing a pid.
fn next_run() -> u64 {
    static RUNS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// mise's bundle separator, spelled as it is upstream.
///
/// Adopted rather than invented: `mise run task1 a b ::: task2 a b` is a shape a
/// caller already knows, and a second separator meaning the same thing is a
/// second vocabulary to learn for nothing.
pub const BUNDLE_SEPARATOR: &str = ":::";

/// Split a trailing argv into the commands it declares.
///
/// No clap change was needed for this and that is worth stating: the tail is
/// already a `Vec<String>` of every token after `--`, so a bundle is a property
/// of the tokens rather than of the parser.
///
/// # Errors
///
/// Returns a [`UsageError`] when the argv declares no command, or declares an
/// empty one — `a ::: ::: b` is a typo, and running two commands where three
/// were written is exactly the silent narrowing a gate must not do.
fn split_bundle(command: &[String]) -> Result<Vec<&[String]>> {
    if command.is_empty() {
        // Unreachable through the CLI: `num_args(1..)` makes clap refuse an empty
        // tail. Kept total because the workspace lints forbid panicking on a
        // reachable path, and a library caller can construct one.
        return Err(UsageError::raise(
            "exec: no command given — write `batten exec -- <cmd> [args…]`",
        ));
    }
    let bundle: Vec<&[String]> = command.split(|token| token == BUNDLE_SEPARATOR).collect();
    if let Some(index) = bundle.iter().position(|segment| segment.is_empty()) {
        return Err(UsageError::raise(format!(
            "exec: command {index} of the `{BUNDLE_SEPARATOR}` bundle is empty"
        )));
    }
    Ok(bundle)
}

/// Run every command in `bundle`, in declaration order, up to `jobs` at a time.
///
/// Returns the outcomes of the commands that RAN. A short list is not an error:
/// without `continue_on_error` a bundle stops at the first failure, and the
/// record says how many of how many ran.
fn dispatch(
    repo_root: &Path,
    bundle: &[&[String]],
    settings: &ExecConfig,
    published: &[(String, String)],
    run: u64,
) -> Result<Vec<Outcome>> {
    let jobs = settings.jobs.max(1);
    let mut done: Vec<Outcome> = Vec::with_capacity(bundle.len());
    // Waves rather than a work-stealing pool: `jobs` is a width, the bundle is
    // short, and a wave boundary is exactly where "stop at the first failure" can
    // be answered without cancelling a child already running. A pool would buy
    // throughput on a workload nobody has.
    for wave in bundle.chunks(jobs) {
        let first = done.len();
        let mut results: Vec<Result<Outcome>> = if wave.len() == 1 {
            // The single-command path stays a plain call, so a bare `batten exec`
            // spawns no thread it does not need — and so the ordinary case is not
            // paying for the bundle case.
            vec![run_one(repo_root, run, first, wave[0], settings, published)]
        } else {
            std::thread::scope(|scope| {
                let handles: Vec<_> = wave
                    .iter()
                    .enumerate()
                    .map(|(offset, command)| {
                        scope.spawn(move || {
                            run_one(repo_root, run, first + offset, command, settings, published)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| {
                        handle
                            .join()
                            .unwrap_or_else(|_| Err(anyhow::anyhow!("exec: a dispatch panicked")))
                    })
                    .collect()
            })
        };
        // Drained in order, so an error from command 2 is reported before one
        // from command 3 even when 3 failed first.
        for result in results.drain(..) {
            done.push(result?);
        }
        if !settings.continue_on_error && done.iter().any(|outcome| outcome.exit != 0) {
            break;
        }
    }
    Ok(done)
}

/// Run one command: spawn it, tee it, capture it, and report nothing.
///
/// Everything that used to be the whole of `run_in_with`, minus the reporting.
/// The split is what `--jobs` forces: with several children in flight nothing may
/// write to a shared stream on the completion path, or the bundle's own output
/// would be ordered by the machine.
fn run_one(
    repo_root: &Path,
    run: u64,
    index: usize,
    command: &[String],
    settings: &ExecConfig,
    published: &[(String, String)],
) -> Result<Outcome> {
    let Some((program, args)) = command.split_first() else {
        return Err(UsageError::raise(
            "exec: no command given — write `batten exec -- <cmd> [args…]`",
        ));
    };

    // THE SAME RESOLUTION EVERY SPAWNING KIND GETS (CLOUD-617). `exec` runs
    // whatever a consumer names, which on Windows is the widest exposure to the
    // two refusals of the lot: an extensionless binary `CreateProcess` will not
    // find, and a shell script it will not read a `#!` for. `.` is the directory
    // this spawn resolves a relative name against, since it inherits the working
    // directory rather than setting one.
    //
    // ONE OBSERVATION, READ TWICE (CLOUD-427). Computed here and carried as a
    // value to the teardown below; see `GroupDecision` for why re-asking is the
    // bug rather than the tidier spelling.
    //
    // AND DECLINED OUTRIGHT ABOVE ONE JOB. Batten reports `128 + the signal it
    // received`, which is one answer; owning N groups at once would make it N,
    // and a supervisor that cannot say what it tore down is not one.
    let decision = GroupDecision::observe(settings.manage_process_group && settings.jobs <= 1);

    // ARMED BEFORE THE SPAWN, and that ordering is CLOUD-746 S3's whole fix.
    // Everything between the spawn and this call used to be a window in which
    // the child was already a group leader while Batten still held the default
    // dispositions — see `Forwarding::arm`. The group is published by `adopt`
    // the moment the child exists.
    let forwarding = Forwarding::arm(decision)?;
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this is the verb's one spawn, and the child's argv, streams and exit code all pass through untouched — an in-process form would be a different verb (CLOUD-285)"
    )]
    let spawned = crate::rules::spawn_resolving(Some(Path::new(".")), program, |program, extra| {
        let mut builder = Command::new(OsString::from(program));
        builder
            .args(extra.iter().map(OsString::from))
            .args(args.iter().map(OsString::from))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .envs(published.iter().map(|(name, value)| (name, value)));
        group_at_spawn(&mut builder, decision);
        builder.spawn()
    });

    let mut child = match spawned {
        Ok(child) => child,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(UsageError::raise(format!(
                "exec: cannot run `{program}`: not found on PATH"
            )));
        }
        Err(err) => {
            return Err(UsageError::raise(format!(
                "exec: cannot run `{program}`: {err}"
            )));
        }
    };

    // THE FIRST STATEMENT AFTER THE SPAWN, deliberately. Everything below this
    // line — two `Drain::spawn` calls, two `Spool::open` calls — is the file IO
    // that used to sit between the child existing and the forwarder existing.
    // The registry is already installed; this only tells it which group.
    forwarding.adopt(child.id())?;

    // A missing pipe is unreachable — both were just requested as `piped()` — but
    // the workspace lints forbid unwrapping on a path the compiler cannot rule
    // out, and an internal error here is honest: it means the spawn lied.
    let (Some(out_pipe), Some(err_pipe)) = (child.stdout.take(), child.stderr.take()) else {
        return Err(anyhow::anyhow!(
            "exec: the spawned child exposed no pipes to tee"
        ));
    };

    // The live-capture key (CLOUD-430): this process, this dispatch, and this
    // command's position. Through the CLI the dispatch is always `0`, so the
    // whole key is derivable by the caller that spawned Batten — which is the
    // point, since printing it would put a pid in Batten's output and §6
    // byte-stability forbids a field that differs between identical runs.
    let key = format!("{}.{run}.{index}", std::process::id());

    // One thread per pipe. See the module docs: draining them in sequence
    // deadlocks as soon as a child fills the one not being read.
    let out_drain = Drain::spawn(
        out_pipe,
        ChildSink::of(settings, program, capture::LiveStream::STDOUT),
        capture::Spool::open(repo_root, capture::LiveStream::STDOUT, &key)?,
    );
    let err_drain = Drain::spawn(
        err_pipe,
        ChildSink::of(settings, program, capture::LiveStream::STDERR),
        capture::Spool::open(repo_root, capture::LiveStream::STDERR, &key)?,
    );

    let group = GroupRecord::write(repo_root, decision, child.id())?;

    let status = child.wait().context("wait for the wrapped command")?;
    let received = forwarding.finish();
    group.clear();

    // Deadline-bounded (see the module docs). A grandchild that inherited the
    // write end keeps the pipe open past the child's own death, and a bare
    // `join()` on that is a hang with no upper bound. The notices are BUFFERED
    // rather than written, so a bundle's diagnostics land in declaration order.
    //
    // ONE BUDGET ACROSS BOTH, taken here rather than per stream: `PIPE_DRAIN_TIMEOUT`
    // and its floor assertion both describe what a leak costs in total, and two
    // fresh deadlines made that twenty seconds (CLOUD-1288).
    let mut notices = Vec::new();
    let drain_started = std::time::Instant::now();
    let (out_bytes, out_spool) =
        out_drain.collect_remaining(drain_started, Stream::Stdout, &mut notices)?;
    let (err_bytes, err_spool) =
        err_drain.collect_remaining(drain_started, Stream::Stderr, &mut notices)?;

    // Both streams are stored, including an empty one: zero bytes is the real
    // answer "the command said nothing", and it must be distinguishable from a run
    // that was never captured at all. The handles are addressable, never printed —
    // emitting them here would put Batten's bookkeeping on a channel this verb
    // promises is the child's (CLOUD-121 owns the verbs that read them).
    //
    // Sealing is `capture::store` unchanged, which is what makes a bundled
    // command's record byte-identical to the same command run on its own.
    let captures = [
        out_spool.seal(repo_root, Stream::Stdout, &out_bytes)?,
        err_spool.seal(repo_root, Stream::Stderr, &err_bytes)?,
    ];

    // A signal Batten was SENT outranks whatever the child died of. A child that
    // ignored TERM and fell to the escalated KILL must not report `137` to a
    // caller that sent `15` — the caller's question is what happened to the
    // command it asked for, and the answer is "the signal you sent stopped it".
    let exit = match received {
        Some(signal) => 128 + signal,
        None => status.code().unwrap_or_else(|| signal_code(status)),
    };

    Ok(Outcome {
        index,
        exit,
        out_bytes,
        err_bytes,
        captures,
        notices,
        received,
    })
}

/// Render everything the bundle has to say, and decide its exit code.
fn report_bundle(
    bundle: &[&[String]],
    outcomes: &[Outcome],
    patterns: &[OutputPattern],
    settings: &ExecConfig,
    report: &mut dyn Write,
) -> Result<ExitCode> {
    for outcome in outcomes {
        report.write_all(&outcome.notices)?;
    }

    // `keep-order` is the one style that cannot be rendered as the bytes arrive:
    // its whole claim is that each stream appears WHOLE, so nothing may be
    // written until both are complete. The sinks discarded during the run and
    // this is where the streams are laid down, in a fixed order.
    if settings.tee
        && !settings.style.suppresses_child()
        && settings.style.style_only() == OutputStyle::KeepOrder
    {
        for outcome in outcomes {
            std::io::stdout().write_all(&outcome.out_bytes)?;
            std::io::stdout().flush()?;
            std::io::stderr().write_all(&outcome.err_bytes)?;
            std::io::stderr().flush()?;
        }
    }

    // THE BUNDLE'S CODE IS THE FIRST NON-ZERO IN DECLARATION ORDER (CLOUD-430),
    // never whichever child happened to finish last. A bundle where command 2 of
    // 3 failed and command 3 succeeded must not report `0`; and reading the
    // FIRST failure rather than the last keeps the answer a property of the
    // bundle rather than of the scheduler, which `--jobs` would otherwise make
    // non-deterministic.
    let code = bundle_code(outcomes);

    // CLOUD-429: the record IS the default answer, and it is emitted before the
    // passthrough below because a non-zero child must not lose it. On `report`,
    // which is stderr: stdout belongs to the wrapped command, so a document
    // there would corrupt one the caller may be parsing.
    if !settings.style.suppresses_batten() {
        Record {
            verb: "exec",
            exit: code,
            declared: bundle.len(),
            commands: outcomes
                .iter()
                .map(|outcome| CommandRecord {
                    index: outcome.index,
                    exit: outcome.exit,
                    captures: &outcome.captures,
                })
                .collect(),
        }
        .emit(settings.format, report)?;
    }

    // BATTEN DIES OF THE SIGNAL BATTEN WAS SENT (CLOUD-746 S2), and this is the
    // module's own boundary applied to the one case that was handled
    // inconsistently rather than a fourth exit shape. The doc above already
    // records that §7's table governs the codes Batten *chooses*, and that a
    // passthrough cannot honour it because the code is not Batten's to choose.
    // A child that dies of a signal is still reported `128 + N` — there Batten
    // is describing the CHILD, which is correct. Batten describing ITSELF with
    // that convention is the wrapper lying about what happened.
    //
    // There is no tradeoff: a shell sets `$?` to `128 + N` for a signalled
    // process anyway, so every `$?`-reading caller sees the same number, while a
    // caller using `waitpid` gains `WIFSIGNALED` — strictly more information.
    // That is exactly why `timeout`, `env`, `nice` and `tini` interrupt a shell
    // loop and `batten exec` did not:
    //
    //     for f in *.toml; do batten exec -- some-check "$f"; done
    //
    // Ctrl-C there killed the child, Batten exited 130, and bash kept looping,
    // because a shell decides whether to abort a loop by checking `WIFSIGNALED`
    // and not by reading the number.
    //
    // AFTER the record and after every capture is sealed, never instantly.
    // Abrupt-death safety is already the documented design — the spool watermark
    // plus the kernel-released `fs4` lock — so re-raising here is strictly safer
    // than the `SIGKILL` case that is already handled, and the caller still gets
    // the record describing what happened before the process goes.
    #[cfg(unix)]
    if let Some(signal) = outcomes.iter().find_map(|outcome| outcome.received) {
        report.flush()?;
        // Restores the default disposition and raises on self, so this does not
        // return. A safe API, already vendored — `unsafe_code = "forbid"` is not
        // the blocker it looks like.
        signal_hook::low_level::emulate_default_handler(signal)
            .context("re-raise the signal Batten was sent")?;
    }

    if code != 0 {
        // Batten only ever ADDS failure (CLOUD-117). A child that already failed
        // needs no promotion, and re-deciding a failure Batten did not diagnose
        // would make the wrapper's verdict unreadable. Its code passes through.
        return Err(Passthrough::raise(code));
    }

    // Only `0` is promotable, and only a declared pattern promotes it.
    let mut found: Vec<Hit> = Vec::new();
    for outcome in outcomes {
        found.extend(outputs::hits(patterns, Stream::Stdout, &outcome.out_bytes));
        found.extend(outputs::hits(patterns, Stream::Stderr, &outcome.err_bytes));
    }
    if found.is_empty() {
        return Ok(ExitCode::Success);
    }

    // Pointer-only (non-negotiable rule 4): `stream:line <id>` per hit, then the
    // count, then each pattern's reason once. Never the matched line — a wrapped
    // command's output is the likeliest place in this whole engine for a secret to
    // appear, which is what makes pointer-only load-bearing here.
    for hit in &found {
        writeln!(report, "{}", hit.line_text())?;
    }
    writeln!(report, "exec: {} output match(es)", found.len())?;
    for reason in outputs::reasons(patterns, &found) {
        writeln!(report, "{reason}")?;
    }
    // Exit 1, not 2: this is a statement that the invocation's own report was
    // untrustworthy, not a rule finding over the repository. Stated on the issue as
    // a chosen asymmetry rather than an oversight.
    Err(UsageError::raise(format!(
        "exec: the wrapped command exited 0 but its output matched {} declared \
         pattern(s) meaning it is not actually done",
        outputs::reasons(patterns, &found).len()
    )))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_command_is_a_usage_error_never_a_verdict() {
        let err = run(&[]).expect_err("an empty command cannot be run");
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn an_absent_program_is_a_usage_error_never_a_verdict() {
        let err = run(&["batten-no-such-program-exists".to_owned()])
            .expect_err("an absent program cannot be run");
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "a program that is not there is a statement about the invocation"
        );
    }

    /// The code `run` reports for a shell exiting `code`.
    #[cfg(unix)]
    fn exit_with(script: &str) -> Result<ExitCode> {
        run(&["sh".to_owned(), "-c".to_owned(), script.to_owned()])
    }

    #[cfg(unix)]
    #[test]
    fn a_clean_child_is_success() {
        assert_eq!(exit_with("exit 0").expect("sh runs"), ExitCode::Success);
    }

    #[cfg(unix)]
    #[test]
    fn the_childs_code_is_reported_unchanged_including_outside_the_table() {
        // The exception, asserted at the unit boundary as well as end-to-end: a
        // code the §7 table does not contain must survive intact.
        for expected in [1, 2, 7, 42, 255] {
            let err =
                exit_with(&format!("exit {expected}")).expect_err("non-zero travels as an error");
            let carried = err
                .downcast_ref::<Passthrough>()
                .expect("a non-zero child code is a Passthrough");
            assert_eq!(carried.0, expected);
            assert_eq!(i32::from(carried.byte()), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_signalled_child_is_never_reported_as_success() {
        // `ExitStatus::code()` is `None` for a signalled child. Reporting `0`
        // there would call a killed build a pass.
        let err = exit_with("kill -TERM $$").expect_err("a signalled child is not success");
        let carried = err
            .downcast_ref::<Passthrough>()
            .expect("a signalled child is a Passthrough");
        assert_ne!(carried.0, 0, "a signalled child must not read as success");
        assert_eq!(
            carried.0,
            128 + 15,
            "the shell's own 128 + signal convention"
        );
    }

    // --- what the caller is charged for (CLOUD-429) --------------------------

    #[test]
    fn the_default_is_a_record_and_the_bytes_are_opt_in() {
        const { assert!(!ExecConfig::DEFAULT.tee) };
        assert_eq!(ExecConfig::DEFAULT.format, OutputFormat::Human);
        assert_eq!(ExecConfig::DEFAULT.style, OutputStyle::Interleave);
    }

    #[test]
    fn style_only_separates_the_stream_style_from_the_suppression() {
        // mise's own function, by its own name, and the distinction the issue is
        // explicit must not collapse into one key: `quiet` is not a way of
        // rendering a line, it is a statement about whose lines are rendered.
        assert_eq!(OutputStyle::Quiet.style_only(), OutputStyle::Interleave);
        assert_eq!(OutputStyle::Silent.style_only(), OutputStyle::Interleave);
        for style in [
            OutputStyle::Prefix,
            OutputStyle::Interleave,
            OutputStyle::KeepOrder,
            OutputStyle::Replacing,
            OutputStyle::Timed,
        ] {
            assert_eq!(style.style_only(), style, "{style:?} IS a stream style");
            assert!(!style.suppresses_batten());
            assert!(!style.suppresses_child());
        }
        assert!(OutputStyle::Quiet.suppresses_batten());
        assert!(
            !OutputStyle::Quiet.suppresses_child(),
            "quiet silences the tool, not the task — that is the whole point of it"
        );
        assert!(OutputStyle::Silent.suppresses_batten());
        assert!(OutputStyle::Silent.suppresses_child());
    }

    #[test]
    fn the_record_names_the_bytes_without_carrying_them() {
        // Rule 4, asserted over the rendering rather than over the type: a field
        // that never holds bytes cannot leak them, and this is the check that the
        // renderer did not go looking for some anyway.
        let captures = [
            capture::Capture {
                stream: "stdout",
                bytes: 11,
                digest: "aa".repeat(32),
            },
            capture::Capture {
                stream: "stderr",
                bytes: 0,
                digest: "bb".repeat(32),
            },
        ];
        let record = Record {
            verb: "exec",
            exit: 7,
            declared: 1,
            commands: vec![CommandRecord {
                index: 0,
                exit: 7,
                captures: &captures,
            }],
        };
        for format in [OutputFormat::Human, OutputFormat::Json, OutputFormat::Jsonl] {
            let mut said = Vec::new();
            record.emit(format, &mut said).expect("the record renders");
            let said = String::from_utf8(said).expect("the record is text");
            assert!(said.contains('7'), "{format:?} dropped the exit code");
            assert!(
                said.contains(&"aa".repeat(32)),
                "{format:?} dropped a digest"
            );
            assert!(said.contains("11"), "{format:?} dropped a byte count");
            // Repeated rendering is identical: §6 byte-stability, and the reason
            // `timed` may not carry a clock.
            let mut again = Vec::new();
            record.emit(format, &mut again).expect("the record renders");
            assert_eq!(said.as_bytes(), again.as_slice());
        }
    }

    #[test]
    fn a_discarding_sink_still_accounts_for_every_byte() {
        // The tee loop writes what it read and expects the count back. A sink
        // that reported a short write because nobody was listening would spin on
        // bytes the capture already has.
        let mut sink = ChildSink::of(&ExecConfig::DEFAULT, "child", capture::LiveStream::STDOUT);
        assert!(sink.discard, "the default shows the caller nothing");
        assert_eq!(sink.write(b"hello").expect("a discard cannot fail"), 5);
    }

    #[test]
    fn a_prefix_lands_at_every_line_start_across_chunk_boundaries() {
        // A pipe splits wherever it likes, so the prefix has to be a function of
        // where the last byte left the line rather than of where a read ended.
        let settings = ExecConfig {
            tee: true,
            style: OutputStyle::Prefix,
            ..ExecConfig::DEFAULT
        };
        let mut sink = ChildSink::of(&settings, "child", capture::LiveStream::STDOUT);
        let mut said = Vec::new();
        sink.dress(&mut said, b"on").expect("write");
        sink.dress(&mut said, b"e\ntw").expect("write");
        sink.dress(&mut said, b"o\n").expect("write");
        assert_eq!(said, b"child| one\nchild| two\n");
    }

    // --- process-group ownership (CLOUD-427) --------------------------------

    #[test]
    fn the_opt_in_defaults_off_so_the_topology_is_unchanged() {
        // The acceptance clause a consumer feels: with nothing declared, `exec`
        // makes no group, installs no disposition and writes no record. Asserted
        // over the default value rather than over an absent config key, because
        // both `run`/`run_in` and an empty `[exec]` table land here.
        const { assert!(!ExecConfig::DEFAULT.manage_process_group) };
        assert_eq!(ExecConfig::default(), ExecConfig::DEFAULT);
        assert!(!GroupDecision::decide(false, false, false).groups());
    }

    #[test]
    fn each_decline_rule_refuses_on_its_own() {
        // mise's two, plus Batten's declaration. Every rule is asserted to be
        // individually sufficient to decline: a predicate that only refuses when
        // several hold at once would pass an "all three off" case and still leak.
        assert!(
            GroupDecision::decide(true, false, false).groups(),
            "opt-in, no ancestor managing, not the session leader: Batten owns it"
        );
        assert!(
            !GroupDecision::decide(true, true, false).groups(),
            "MISE_TASK_PGID_MANAGED means an ancestor already manages the group"
        );
        assert!(
            !GroupDecision::decide(true, false, true).groups(),
            "a session leader manages nothing an ancestor was not already placed to"
        );
        assert!(
            !GroupDecision::decide(false, false, false).groups(),
            "the residual case is declared, never inferred — off means off"
        );
    }

    #[test]
    fn the_decision_is_observed_exactly_once_per_run() {
        // "Computed once and read again" is the property, and it is structural
        // rather than behavioural: two observations could disagree (a `setsid`
        // in between, an inherited marker) and the failure is silent — only the
        // direct pid gets the signal, and the grandchildren leak. So the source
        // is asserted to contain exactly one observation, in the run body, with
        // every later reader taking the value.
        // Counted over the module's own code, never over this file whole: the
        // needle appears in this very assertion, and a test that counts itself
        // reports a number nobody can reason about.
        let source = include_str!("exec.rs");
        let shipped = source
            .split("#[cfg(test)]")
            .next()
            .expect("the module has code before its tests");
        let observations = shipped.matches("GroupDecision::observe(").count();
        assert_eq!(
            observations, 1,
            "expected exactly one observation, in `run_in_with`. A second call \
             site means the spawn and the teardown can disagree, which is \
             CLOUD-427's own bug."
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_marker_batten_reads_is_the_marker_mise_writes() {
        // A protocol token shared with another tool. Spelling it differently
        // would not be a rename, it would be a silent opt-out: Batten would stop
        // seeing mise's marker and mise would stop seeing Batten's, and both ends
        // would group.
        assert_eq!(TASK_PGID_MANAGED_ENV, "MISE_TASK_PGID_MANAGED");
    }

    #[cfg(unix)]
    #[test]
    fn grouping_always_propagates_the_marker() {
        // Without the propagation, grouping is strictly worse than not grouping:
        // a nested mise groups again under Batten's group, so Batten's `killpg`
        // reaches mise and not the leaves. Asserted on the builder rather than on
        // a live child, because `process_group` has no getter — what is checkable
        // is that the two are set by one function and cannot be separated.
        let source = include_str!("exec.rs");
        let body = source
            .split("fn group_at_spawn(builder: &mut Command, decision: GroupDecision) {")
            .nth(1)
            .expect("the unix grouping function is declared here");
        let body = &body[..body.find("\n}").expect("the function closes")];
        assert!(body.contains(".process_group(0)"), "it must make the group");
        assert!(
            body.contains(".env(TASK_PGID_MANAGED_ENV"),
            "and it must tell a nested manager to stand down, in the same call"
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_the_four_job_control_signals_are_forwarded() {
        // KILL is absent because it cannot be caught — that case is recordable,
        // never preventable — and USR1/USR2 are absent because they mean whatever
        // a consumer's tooling has agreed they mean.
        assert_eq!(
            FORWARDED,
            [
                signal_hook::consts::SIGHUP,
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGQUIT,
                signal_hook::consts::SIGTERM,
            ]
        );
        assert!(!FORWARDED.contains(&signal_hook::consts::SIGKILL));
    }

    #[cfg(unix)]
    #[test]
    fn an_unmanaged_run_installs_nothing_and_records_nothing() {
        let decision = GroupDecision::decide(false, false, false);
        let forwarding = Forwarding::arm(decision).expect("no forwarder to install");
        forwarding
            .adopt(std::process::id())
            .expect("adopting an unmanaged run is a no-op");
        assert_eq!(
            forwarding.finish(),
            None,
            "nothing was forwarded, so the child's own status is the answer"
        );

        // A path that does not exist, on purpose: an unmanaged run must not so
        // much as resolve the state directory, and this case fails loudly if it
        // starts to.
        let record = GroupRecord::write(Path::new("/batten-no-such-repo"), decision, 4242)
            .expect("an unmanaged run writes no record");
        assert!(record.path.is_none());
    }

    /// A spool under this process's own scratch directory.
    ///
    /// `Spool::open_in` rather than `Spool::open`: resolving the state root reads
    /// the OS data directory, and a unit test must not write into a developer's.
    fn scratch_spool(name: &str, stream: capture::LiveStream) -> capture::Spool {
        let dir = std::env::temp_dir().join(format!("batten-exec-unit-{}", std::process::id()));
        capture::Spool::open_in(&dir, stream, name).expect("open a scratch spool")
    }

    #[test]
    fn the_drain_reports_what_arrived_when_the_pipe_never_closes() {
        // The live hang CLOUD-162 introduced and this issue bounds: EOF arrives
        // when the LAST holder of the write end closes it, which is not the
        // moment the child is reaped. Modelled with a reader that never sees EOF
        // — the case cannot pass at all without the deadline, because a bare
        // `join()` on this shape does not return.
        struct NeverEnds {
            /// One chunk, then silence forever.
            spoken: bool,
        }
        impl Read for NeverEnds {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.spoken {
                    #[expect(
                        clippy::disallowed_methods,
                        reason = "the only site in the crate where the delay IS the subject: \
                                  `NeverEnds` models a pipe whose write end never closes, so the \
                                  hour is a stand-in for `read` never returning. The bound is the \
                                  caller's — `collect_within` gives up on its own deadline, which \
                                  is the property under test (CLOUD-1177)"
                    )]
                    std::thread::sleep(Duration::from_hours(1));
                    return Ok(0);
                }
                self.spoken = true;
                let said = b"partial";
                buf.get_mut(..said.len())
                    .ok_or_else(|| std::io::Error::other("buffer too small"))?
                    .copy_from_slice(said);
                Ok(said.len())
            }
        }

        let drain = Drain::spawn(
            NeverEnds { spoken: false },
            std::io::sink(),
            scratch_spool("never-ends", capture::LiveStream::STDOUT),
        );
        // Wait for the one chunk to land, so the case asserts "kept what arrived"
        // rather than accidentally asserting "gave up before anything did".
        while drain.seen.lock().map_or(true, |held| held.is_empty()) {
            #[expect(
                clippy::disallowed_methods,
                reason = "the interval of a poll whose exit condition is the `seen` buffer holding \
                          the one chunk `NeverEnds` speaks; without it the case would assert \
                          \"gave up before anything arrived\" instead (CLOUD-1177)"
            )]
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut report = Vec::new();
        let (bytes, _spool) = drain
            .collect_within(Duration::from_millis(200), Stream::Stdout, &mut report)
            .expect("a drain that timed out is not a failed command");
        assert_eq!(
            bytes, b"partial",
            "the bytes that did arrive are still stored"
        );
        let said = String::from_utf8(report).expect("the report is text");
        assert!(
            said.contains("did not reach EOF") && said.contains("7 byte(s)"),
            "a truncated capture must say so, as a count: {said}"
        );
        assert!(
            !said.contains("partial"),
            "pointer-only (rule 4): the notice names a count, never the bytes"
        );
    }

    #[test]
    fn a_drain_that_reaches_eof_reports_nothing_at_all() {
        // The other half, and the one that runs on every ordinary command: no
        // notice on the happy path, or `exec` would be writing on a channel it
        // promises is the child's.
        let drain = Drain::spawn(
            &b"hello"[..],
            std::io::sink(),
            scratch_spool("clean-eof", capture::LiveStream::STDOUT),
        );
        let mut report = Vec::new();
        let (bytes, _spool) = drain
            .collect_within(PIPE_DRAIN_TIMEOUT, Stream::Stdout, &mut report)
            .expect("clean EOF");
        assert_eq!(bytes, b"hello");
        assert!(report.is_empty(), "the happy path emits nothing");
    }

    /// The zero-remaining case, and it is an OUTPUT property rather than a data
    /// one (CLOUD-1288).
    ///
    /// Once the two drains share one budget, the second stream's deadline can
    /// legitimately be `Duration::ZERO` — the first spent it all. A stderr whose
    /// tee finished cleanly seconds earlier must still emit NOTHING: a "did not
    /// reach EOF" pointer on a healthy stream is a false finding on a channel
    /// house-style §6 requires to be byte-stable, and it would fire on exactly
    /// the runs the shared budget exists to speed up.
    ///
    /// # What this case does and does not discriminate, measured rather than assumed
    ///
    /// CLOUD-1288 predicted this would fail against a naive `saturating_sub`,
    /// on the premise that `recv_timeout(Duration::ZERO)` can report `Timeout`
    /// without examining a value already in the channel. **That does not
    /// reproduce on this toolchain**: 10,000 trials over a channel holding a
    /// ready value returned it 10,000 times and reported `Timeout` zero times.
    ///
    /// So this case pins the property rather than separating the two spellings,
    /// and that is worth saying plainly instead of claiming a discrimination it
    /// does not have. The `try_recv` in `collect_within` stands anyway, because
    /// "has this stream already finished" and "how long may I wait" are different
    /// questions, and answering the first through the second leaves the notice
    /// depending on an `mpsc` detail std does not promise.
    #[test]
    fn a_finished_stream_emits_no_notice_when_the_budget_is_gone() {
        let drain = Drain::spawn(
            &b"hello"[..],
            std::io::sink(),
            scratch_spool("zero-budget", capture::LiveStream::STDERR),
        );
        // The tee appends before it reports, so wait for the bytes and then for
        // the outcome to follow them. Same poll idiom as the timeout case above,
        // and for the same reason: without it this would assert "gave up before
        // anything arrived", which is the opposite property.
        while drain.seen.lock().map_or(true, |held| held.len() < 5) {
            #[expect(
                clippy::disallowed_methods,
                reason = "the interval of a poll whose exit condition is the `seen` buffer holding \
                          the bytes the tee speaks; the case is about what happens AFTER a stream \
                          finished, so it has to wait for it to finish (CLOUD-1177)"
            )]
            std::thread::sleep(Duration::from_millis(10));
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the tee appends to `seen` and only then sends its outcome, so the poll above \
                      can exit inside that window; this closes it. The subject is a stream that \
                      has ALREADY finished, and racing its own completion would test the other \
                      case (CLOUD-1288)"
        )]
        std::thread::sleep(Duration::from_millis(200));

        let mut report = Vec::new();
        let (bytes, _spool) = drain
            .collect_within(Duration::ZERO, Stream::Stderr, &mut report)
            .expect("a finished stream is not a failed command");
        assert_eq!(bytes, b"hello", "the bytes are taken regardless");
        assert!(
            report.is_empty(),
            "a stream that reached EOF must emit no notice even at a zero \
             remaining budget — the notice says a process still holds the pipe \
             open, and none does: {}",
            String::from_utf8_lossy(&report)
        );
    }

    #[test]
    fn the_drain_deadline_is_long_enough_to_be_about_a_leak() {
        // A deadline short enough to fire on a slow-but-healthy command would
        // truncate real captures, which is a false negative in every gate reading
        // the store. Ten seconds after the child is already reaped is a leak.
        assert!(PIPE_DRAIN_TIMEOUT >= Duration::from_secs(10));
        // `cfg(unix)` with the mechanism it belongs to: Windows has no group to
        // give a grace period, and `cross-check` denies warnings there, so an
        // unconditional reference is a build failure on a platform that has
        // nothing to assert.
        #[cfg(unix)]
        assert!(GROUP_GRACE >= Duration::from_secs(5));
    }

    #[test]
    fn a_code_outside_one_byte_saturates_rather_than_truncating() {
        // Truncation could turn a failure into a success: `0x100` would report
        // `0`. Only a non-POSIX child can produce one, but the direction matters.
        assert_eq!(Passthrough(0x100).byte(), u8::MAX);
        assert_eq!(Passthrough(-1).byte(), u8::MAX);
        assert_eq!(Passthrough(7).byte(), 7);
    }
}
