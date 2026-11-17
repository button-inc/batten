//! The process adapter over [`crate::stream`] (#1276): every capture of a
//! child's streams goes through [`Streamed`] or [`StreamedChild`].
//!
//! Under `capture`, not `exec`: `secrets` reached `exec` for it, which pulled
//! `task` along and took `secrets` past the deepest closure
//! `tests/it/module_closure.rs` records, and a new leaf module under `exec`
//! added one to every module spawning through `exec`. `capture` is already in
//! both closures, so the move adds an edge to neither. It reaches nothing in
//! this crate; `batten-stream` is I/O alone, and this is where a `Command`
//! meets it, under the spawn-placement table's `capture` row.

use std::io::Read;

/// [`std::process::Command::output`] and [`std::process::Child::wait_with_output`],
/// with every stream through [`pump`](crate::stream::pump) (#1276).
///
/// The same [`std::process::Output`] comes back, so a call site changes only
/// its method name. What changes underneath: stdin is closed as `output` closes
/// it, and stdout and stderr are each pumped on their own thread
/// ([`spawn_pump`](crate::stream::spawn_pump)) into a [`Shared`](crate::stream::Shared) buffer chunk by chunk while the child
/// runs, instead of `std`'s private read-to-end. A caller that also wants the
/// bytes live, or in a spool, pumps the child's pipes itself into those sinks.
pub trait Streamed {
    /// The child's status and both streams, pumped as they were written. Every
    /// stream takes `output`'s default: stdin closed, stdout and stderr piped.
    ///
    /// # Errors
    ///
    /// The child cannot be started or waited for.
    fn streamed_output(&mut self) -> std::io::Result<std::process::Output> {
        self.streamed_output_keeping(Keep::NONE)
    }

    /// [`Streamed::streamed_output`] for a command whose caller already set
    /// some of its streams: each stream `keep` names is left exactly as set,
    /// and only the others take `output`'s default. A kept stream that is not a
    /// pipe captures nothing, as under `output`.
    ///
    /// `std` cannot be asked which streams a `Command` already has, and
    /// `output` alone knows; so the caller says, and the `stream-keep-set`
    /// recipe (`crates/batten-codemods`) said it at every chain that set one.
    ///
    /// # Errors
    ///
    /// The child cannot be started or waited for.
    fn streamed_output_keeping(&mut self, keep: Keep) -> std::io::Result<std::process::Output>;
}

/// Which of a command's streams its caller set before capturing it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Keep {
    /// Stdin was set.
    pub stdin: bool,
    /// Stdout was set.
    pub stdout: bool,
    /// Stderr was set.
    pub stderr: bool,
}

impl Keep {
    /// No stream was set: every one takes `output`'s default.
    pub const NONE: Self = Self {
        stdin: false,
        stdout: false,
        stderr: false,
    };
}

#[expect(
    clippy::disallowed_types,
    reason = "stays: this impl IS the census's one capture route — every spawn site that \
              reads its child's output reaches its streams through here, not its own loop (#1276)"
)]
impl Streamed for std::process::Command {
    fn streamed_output_keeping(&mut self, keep: Keep) -> std::io::Result<std::process::Output> {
        if !keep.stdin {
            self.stdin(std::process::Stdio::null());
        }
        if !keep.stdout {
            self.stdout(std::process::Stdio::piped());
        }
        if !keep.stderr {
            self.stderr(std::process::Stdio::piped());
        }
        self.spawn()?.streamed_wait()
    }
}

/// [`std::process::Child::wait_with_output`] through [`pump`](crate::stream::pump).
pub trait StreamedChild {
    /// Close stdin, pump whichever of stdout and stderr were piped while the
    /// child runs, wait for it, and return what each said.
    ///
    /// # Errors
    ///
    /// The child cannot be waited for.
    fn streamed_wait(self) -> std::io::Result<std::process::Output>;
}

impl StreamedChild for std::process::Child {
    fn streamed_wait(mut self) -> std::io::Result<std::process::Output> {
        // Closed first, as `wait_with_output` does: a child reading stdin to EOF
        // would otherwise wait on a pipe this end still holds open.
        drop(self.stdin.take());
        let drain = |pipe: Option<Box<dyn Read + Send>>| {
            let buffer = crate::stream::Shared::new(Vec::new());
            let pumping =
                pipe.map(|pipe| crate::stream::spawn_pump(pipe, vec![Box::new(buffer.clone())]));
            (buffer, pumping)
        };
        let (out, out_pump) = drain(
            self.stdout
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
        );
        let (err, err_pump) = drain(
            self.stderr
                .take()
                .map(|pipe| Box::new(pipe) as Box<dyn Read + Send>),
        );
        let status = self.wait()?;
        for pumping in [out_pump, err_pump].into_iter().flatten() {
            if let crate::stream::Pumped::Finished(Err(why)) =
                pumping.finished(crate::stream::DRAIN_GRACE)
            {
                return Err(why);
            }
        }
        Ok(std::process::Output {
            status,
            stdout: out.bytes(),
            stderr: err.bytes(),
        })
    }
}
