//! THE ONE STREAM IMPLEMENTATION (#1276): every byte this engine reads from a
//! child process, and every byte it hands one, moves through [`pump`].
//!
//! **One copy loop, three properties, no exceptions.**
//!
//! * *Chunk by chunk.* A chunk is written onward the moment it is read. Nothing
//!   is held past one chunk, so a minutes-long child's output is visible while
//!   it runs: reading to the end and writing afterwards made #1276's 485-second
//!   schema build look hung.
//! * *Backpressure.* Every write blocks until its sink takes the chunk, and the
//!   next read waits for every write. A slow sink stalls the read, the pipe
//!   fills, and the child's own write blocks: pressure reaches the writer
//!   instead of growing a buffer here.
//! * *Every sink, in order.* A tee is [`pump`] with several sinks. Each takes
//!   each chunk before the next sink does, so a sink a concurrent reader can see
//!   (a capture spool) is never behind one only this process can.
//!
//! **Built on it, nothing else:** [`Shared`] makes a buffer or a spool a sink a
//! caller can read while the pump still runs, and [`spawn_pump`] runs a pump on
//! a thread of its own for a pipe the caller must not block on. A caller that
//! writes its own read loop over a child's pipe is a second implementation,
//! which is the defect this module exists to end.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

/// The size of one chunk. A pipe's atomic write is 4 KiB on Linux, so 8 KiB
/// takes a whole such write and the next in one read.
const CHUNK: usize = 8192;

/// Copy `pipe` to every sink in `sinks`, chunk by chunk, until EOF.
///
/// Each chunk is written whole and flushed to every sink, in order, before the
/// next is read. An interrupted read is retried; any other read error, and any
/// sink refusing a write, stops the pump and is returned.
///
/// # Errors
///
/// The pipe cannot be read, or a sink refuses a write or a flush.
pub fn pump<R: Read>(mut pipe: R, sinks: &mut [&mut dyn Write]) -> std::io::Result<()> {
    let mut chunk = [0_u8; CHUNK];
    loop {
        let read = match pipe.read(&mut chunk) {
            Ok(0) => return Ok(()),
            Ok(read) => read,
            Err(why) if why.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(why) => return Err(why),
        };
        let bytes = chunk.get(..read).unwrap_or(&[]);
        for sink in sinks.iter_mut() {
            sink.write_all(bytes)?;
            sink.flush()?;
        }
    }
}

/// A sink behind a lock, readable by its owner while a pump writes it.
///
/// Cloning shares the sink. Each chunk is written under the lock, so a reader
/// taking the lock sees whole chunks, never a torn one. A poisoned lock means a
/// writer panicked mid-chunk; the write that finds it reports it, and the pump
/// stops rather than writing past a sink in an unknown state.
#[derive(Debug, Default)]
pub struct Shared<W>(Arc<Mutex<W>>);

impl<W> Clone for Shared<W> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<W> Shared<W> {
    /// Share `sink`.
    pub fn new(sink: W) -> Self {
        Self(Arc::new(Mutex::new(sink)))
    }

    /// Run `read` over the sink as it stands now, or `None` over a poisoned lock.
    pub fn with<T>(&self, read: impl FnOnce(&W) -> T) -> Option<T> {
        self.0.lock().ok().map(|held| read(&held))
    }

    /// Run `change` over the sink, or `None` over a poisoned lock.
    pub fn with_mut<T>(&self, change: impl FnOnce(&mut W) -> T) -> Option<T> {
        self.0.lock().ok().map(|mut held| change(&mut held))
    }

    /// The sink by value once nothing else shares it: `Ok(Some)`, or
    /// `Ok(None)` over a poisoned lock. `Err` hands the share back while a
    /// pump still holds one — a pump abandoned at its deadline does.
    ///
    /// # Errors
    ///
    /// Another clone, a running pump's, still shares the sink.
    pub fn into_inner(self) -> Result<Option<W>, Self> {
        Arc::try_unwrap(self.0)
            .map(|held| held.into_inner().ok())
            .map_err(Self)
    }
}

impl Shared<Vec<u8>> {
    /// The bytes written so far, copied out. Empty over a poisoned lock: the
    /// only writer is a pump, so poison means it panicked and there is nothing
    /// trustworthy to read.
    #[must_use]
    pub fn bytes(&self) -> Vec<u8> {
        self.with(Clone::clone).unwrap_or_default()
    }
}

impl<W: Write> Write for Shared<W> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("stream: a shared sink was poisoned"))?
            .write(bytes)
    }

    fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("stream: a shared sink was poisoned"))?
            .write_all(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0
            .lock()
            .map_err(|_| std::io::Error::other("stream: a shared sink was poisoned"))?
            .flush()
    }
}

/// A [`pump`] running on a thread of its own.
///
/// The thread is detached on purpose: a writer that left its process group can
/// hold a pipe open forever, and a join would wait with it. What the pump wrote
/// is in its sinks either way, so the caller waits as long as it chooses
/// ([`Pumping::finished`]) and then reads them.
#[derive(Debug)]
pub struct Pumping {
    done: mpsc::Receiver<std::io::Result<()>>,
}

/// Where a [`Pumping`] stands.
#[derive(Debug)]
pub enum Pumped {
    /// It reached EOF (`Ok`) or stopped on a read or write error (`Err`).
    Finished(std::io::Result<()>),
    /// It is still running.
    Running,
    /// Its thread ended without a result — it panicked. What it wrote before is
    /// in its sinks and is real; there is no result to report.
    Lost,
}

impl Pumping {
    /// Where the pump stands after waiting at most `within` for it to finish.
    /// Zero asks without waiting.
    #[must_use]
    pub fn finished(&self, within: Duration) -> Pumped {
        // A NON-BLOCKING TAKE FIRST: `recv_timeout(ZERO)` may report a timeout
        // without looking at a result that is already waiting (CLOUD-1288).
        match self.done.try_recv() {
            Ok(result) => Pumped::Finished(result),
            Err(mpsc::TryRecvError::Disconnected) => Pumped::Lost,
            Err(mpsc::TryRecvError::Empty) => match self.done.recv_timeout(within) {
                Ok(result) => Pumped::Finished(result),
                Err(mpsc::RecvTimeoutError::Timeout) => Pumped::Running,
                Err(mpsc::RecvTimeoutError::Disconnected) => Pumped::Lost,
            },
        }
    }
}

impl Pumping {
    /// A pump in a state a test sets: nothing reported until the returned
    /// sender sends, and never if the sender is held unsent. Built rather than
    /// raced (CLOUD-2059): the state under test is constructed, not waited for.
    #[cfg(any(test, feature = "seam"))]
    #[must_use]
    pub fn held() -> (Self, mpsc::Sender<std::io::Result<()>>) {
        let (tx, done) = mpsc::channel();
        (Self { done }, tx)
    }
}

/// Pump `pipe` into `sinks` on a thread of its own ([`Pumping`]).
#[must_use]
pub fn spawn_pump<R>(pipe: R, mut sinks: Vec<Box<dyn Write + Send>>) -> Pumping
where
    R: Read + Send + 'static,
{
    let (tx, done) = mpsc::channel();
    drop(std::thread::spawn(move || {
        let mut held: Vec<&mut dyn Write> = sinks
            .iter_mut()
            .map(|sink| sink.as_mut() as &mut dyn Write)
            .collect();
        let _ = tx.send(pump(pipe, &mut held));
    }));
    Pumping { done }
}

/// How long a finished child's pipes have to reach EOF once it is reaped: a
/// grandchild still holding a write end means EOF never comes, so the wait for
/// it is bounded and what arrived is kept.
pub const DRAIN_GRACE: Duration = Duration::from_secs(10);

/// [`std::process::Command::output`] and [`std::process::Child::wait_with_output`],
/// with every stream through [`pump`] (#1276).
///
/// The same [`std::process::Output`] comes back, so a call site changes only
/// its method name. What changes underneath: stdin is closed as `output` closes
/// it, and stdout and stderr are each pumped on their own thread
/// ([`spawn_pump`]) into a [`Shared`] buffer chunk by chunk while the child
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

/// [`std::process::Child::wait_with_output`] through [`pump`].
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
            let buffer = Shared::new(Vec::new());
            let pumping = pipe.map(|pipe| spawn_pump(pipe, vec![Box::new(buffer.clone())]));
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
            if let Pumped::Finished(Err(why)) = pumping.finished(DRAIN_GRACE) {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A pipe that yields `chunks` one per read, and on each read records what
    /// both sinks already held: the pump's ordering, observed.
    struct Pipe {
        chunks: Vec<&'static [u8]>,
        first: Shared<Vec<u8>>,
        second: Shared<Vec<u8>>,
        held_at_read: Vec<(usize, usize)>,
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.held_at_read
                .push((self.first.bytes().len(), self.second.bytes().len()));
            if self.chunks.is_empty() {
                return Ok(0);
            }
            let chunk = self.chunks.remove(0);
            buf[..chunk.len()].copy_from_slice(chunk);
            Ok(chunk.len())
        }
    }

    struct Refuses;

    impl Write for Refuses {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("full"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn pipe(chunks: Vec<&'static [u8]>) -> Pipe {
        Pipe {
            chunks,
            first: Shared::default(),
            second: Shared::default(),
            held_at_read: Vec::new(),
        }
    }

    /// Fails by: a chunk held past the next read (output shown late, or only
    /// at the end), a sink skipped, or the bytes changed on the way.
    #[test]
    fn every_chunk_reaches_every_sink_before_the_next_read() {
        let mut source = pipe(vec![b"abc", b"de", b"f"]);
        let (mut one, mut two) = (source.first.clone(), source.second.clone());
        pump(&mut source, &mut [&mut one, &mut two]).expect("pumped");
        assert_eq!(one.bytes(), b"abcdef");
        assert_eq!(two.bytes(), b"abcdef");
        assert_eq!(
            source.held_at_read,
            vec![(0, 0), (3, 3), (5, 5), (6, 6)],
            "each chunk reached both sinks before the next read"
        );
    }

    /// Fails by: a refusal swallowed (the pump reads on past a sink that took
    /// nothing), or a later sink written ahead of an earlier one.
    #[test]
    fn a_refusing_sink_stops_the_pump_before_any_later_sink_or_read() {
        let mut source = pipe(vec![b"x", b"y"]);
        let mut late = Shared::<Vec<u8>>::default();
        assert!(pump(&mut source, &mut [&mut Refuses, &mut late]).is_err());
        assert_eq!(source.held_at_read.len(), 1, "no read after a refusal");
        assert!(
            late.bytes().is_empty(),
            "no later sink ahead of an earlier one"
        );
    }

    /// Fails by: an interrupted read treated as the end or as a failure.
    #[test]
    fn an_interrupted_read_is_retried() {
        struct Interrupts(bool);
        impl Read for Interrupts {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0 {
                    return Ok(0);
                }
                if buf[0] == 0 {
                    buf[0] = 1;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.0 = true;
                buf[0] = b'z';
                Ok(1)
            }
        }
        let mut seen = Shared::<Vec<u8>>::default();
        pump(Interrupts(false), &mut [&mut seen]).expect("pumped");
        assert_eq!(seen.bytes(), b"z");
    }

    /// Fails by: a stream lost or crossed, the status dropped, stdin left open
    /// (the child hangs reading it), or a stream past one pipe's 64 KiB
    /// deadlocking against the wait.
    #[test]
    fn streamed_output_is_output_with_every_stream_pumped() {
        // `sh`, `cat` and `/dev/zero`: a unix contract, compiled everywhere.
        if !cfg!(unix) {
            return;
        }
        #[expect(
            clippy::disallowed_types,
            reason = "stays: the case IS a spawn, because the primitive's contract is about a real child's pipes"
        )]
        let ran = std::process::Command::new("sh")
            .args([
                "-c",
                "cat; head -c 200000 /dev/zero | tr '\\0' o; head -c 200000 /dev/zero | tr '\\0' e >&2; exit 3",
            ])
            .streamed_output()
            .expect("sh runs");
        assert_eq!(ran.status.code(), Some(3));
        assert_eq!(ran.stdout.len(), 200_000);
        assert!(ran.stdout.iter().all(|byte| *byte == b'o'));
        assert_eq!(ran.stderr.len(), 200_000);
        assert!(ran.stderr.iter().all(|byte| *byte == b'e'));
    }

    /// Fails by: a stream the caller set overwritten (here a stdin read from a
    /// file becomes closed, and the child reads nothing), or a stream the
    /// caller did not name left without `output`'s default.
    #[test]
    fn a_kept_stream_is_left_as_the_caller_set_it() {
        // `sh`, `cat` and `/dev/zero`: a unix contract, compiled everywhere.
        if !cfg!(unix) {
            return;
        }
        let dir = std::env::temp_dir().join(format!("batten-stream-keep-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let input = dir.join("in");
        std::fs::write(&input, "from the file").unwrap();
        let cat = |keep: Keep| {
            #[expect(
                clippy::disallowed_types,
                reason = "stays: the case IS a spawn, because the primitive's contract is about a real child's pipes"
            )]
            let mut command = std::process::Command::new("cat");
            command
                .stdin(std::fs::File::open(&input).unwrap())
                .streamed_output_keeping(keep)
                .unwrap()
        };
        let kept = cat(Keep {
            stdin: true,
            ..Keep::NONE
        });
        assert_eq!(kept.stdout, b"from the file");
        let defaulted = cat(Keep::NONE);
        assert!(defaulted.stdout.is_empty(), "an unnamed stdin is closed");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fails by: a spawned pump's result lost, its sinks unwritten, or a
    /// finished pump reported as still running when asked without waiting.
    #[test]
    fn a_spawned_pump_reports_eof_and_its_sinks_are_readable() {
        let seen = Shared::<Vec<u8>>::default();
        let pumping = spawn_pump(&b"hello"[..], vec![Box::new(seen.clone())]);
        assert!(matches!(
            pumping.finished(Duration::from_secs(10)),
            Pumped::Finished(Ok(()))
        ));
        assert_eq!(seen.bytes(), b"hello");
    }
}
