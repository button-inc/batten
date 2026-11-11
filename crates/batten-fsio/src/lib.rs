//! Every filesystem read this crate makes, in one place (CLOUD-2692).
//!
//! # Why one module
//!
//! The crate is a heavy reader, and it read 385 places directly through
//! `std::fs`, each choosing for itself whether to buffer, batch or stream. A
//! read routed here is one the crate can change in one place: batch it with its
//! siblings, stream it in bounded chunks, or put it on a completion queue. A
//! ratchet row in `batten.toml` keeps a direct `std::fs` read from growing back
//! anywhere else.
//!
//! # What each entry point does today, measured
//!
//! * [`read_many`] submits every read before awaiting any, through compio: on
//!   Linux one `io_uring` batch (falling back to compio's pool where the ring is
//!   refused), IOCP on Windows, a pool on macOS. Each file is ONE read of its
//!   known size; a growing buffer chains a read per doubling and measured
//!   slower than not batching at all.
//! * [`read_to_string`] and [`read`] are one file, read synchronously: a lone
//!   read has nothing to batch with, and a ring set up for one read costs more
//!   than the read. They are the seam a caller moves off when it can name its
//!   files together.
//!
//! # Effect
//!
//! Reads only. Reaches nothing in this crate, so it is a LEAF.

use std::io;
use std::path::{Path, PathBuf};

/// One file's text. See the module doc for why a lone read is synchronous.
///
/// # Errors
///
/// As [`std::fs::read_to_string`].
pub fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
    std::fs::read_to_string(path)
}

/// One file's bytes. See the module doc for why a lone read is synchronous.
///
/// # Errors
///
/// As [`std::fs::read`].
pub fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

/// The bytes of every one of `files`, each given with its size from a stat the
/// caller already took, with every read in flight before any completes.
///
/// Each read is spawned onto one compio runtime before the first is awaited,
/// so a cold page cache is served at the device's queue depth rather than one
/// file at a time. Where no runtime can be built the files are read here, in
/// order. `None` is a file that could not be read.
#[must_use]
pub fn read_many(files: &[(PathBuf, u64)]) -> Vec<Option<Vec<u8>>> {
    let Ok(runtime) = compio::runtime::Runtime::new() else {
        return files
            .iter()
            .map(|(path, _)| std::fs::read(path).ok())
            .collect();
    };
    runtime.block_on(async {
        use compio::io::AsyncReadAtExt as _;
        let reads: Vec<_> = files
            .iter()
            .cloned()
            .map(|(path, size)| {
                compio::runtime::spawn(async move {
                    let file = compio::fs::File::open(&path).await?;
                    let buffer = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
                    let compio::BufResult(read, buffer) = file.read_exact_at(buffer, 0).await;
                    read.map(|()| buffer)
                })
            })
            .collect();
        let mut out = Vec::with_capacity(reads.len());
        for read in reads {
            out.push(read.await.ok().and_then(Result::ok));
        }
        out
    })
}
