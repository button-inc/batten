//! Captured child output, content-addressed in out-of-tree state (CLOUD-162).
//!
//! The shared substrate two capabilities need over the output of a single
//! `batten exec` run: an output predicate that scans it for a pattern meaning
//! "not actually done" (CLOUD-117), and a handle an agent can expand without
//! re-running the command (CLOUD-121). Built once, here, so neither consumer
//! grows its own copy — building the capture twice is the failure the issue
//! exists to prevent.
//!
//! ## What this module is, and is not
//!
//! It is the *storage and addressing* of bytes a child already wrote. It renders
//! no verdict, scans for nothing, and emits nothing: the predicate is CLOUD-117's
//! and the `show` verbs are CLOUD-121's. Keeping it inert is what lets both land
//! on top of it without renegotiating where captures live.
//!
//! ## Addressing reuses the one hashing discipline
//!
//! [`crate::identity::capture_fingerprint`] — a domain tag then each field,
//! length-prefixed, the same construction every finding identity and the config
//! epoch already go through. The digest **is** the key: a capture is stored at
//! `captures/<digest>`, so identical bytes are one record rather than two, and
//! re-running a command whose output did not change writes nothing new.
//!
//! That is also why the record carries no timestamp. A capture keyed by content
//! must be a pure function of that content, and a "captured at" field would make
//! two identical outputs two different records — the byte-stability §6 requires,
//! broken by a field nothing reads.
//!
//! ## Why it lives out of tree
//!
//! [`crate::state::repo_state_dir`] — the same root the receipt store uses, so a
//! checkout stays clean and no new path scheme is invented. A capture is a fact
//! about one run of one command; it is not source, and a repo that accumulated
//! them would have to gitignore its own bookkeeping.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::identity;
use crate::state;

/// Which of a child's two output streams a capture holds.
///
/// A named pair rather than a bare string, so the stored key and the hashed
/// field cannot drift apart, and so a caller cannot invent a third stream the
/// reader will not recognise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Stream {
    /// The child's standard output.
    Stdout,
    /// The child's standard error.
    Stderr,
}

impl Stream {
    /// Both streams, so anything ranging over them is derived rather than typed
    /// twice.
    pub const ALL: &'static [Stream] = &[Stream::Stdout, Stream::Stderr];

    /// The stable token used in the store key and in the hashed preimage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Stream::Stdout => "stdout",
            Stream::Stderr => "stderr",
        }
    }
}

/// A pointer to captured bytes: which stream, how many bytes, and their digest.
///
/// Pointer-only by construction (non-negotiable rule 4) — the record names the
/// bytes and never carries them, which is what lets it be emitted or logged
/// without leaking a program's output.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Capture {
    /// The stream these bytes came from.
    pub stream: &'static str,
    /// How many bytes were captured. Zero is a real answer, not an absence.
    pub bytes: u64,
    /// The content digest, lowercase hex — and the key the bytes are stored at.
    pub digest: String,
}

impl Capture {
    /// The handle a consumer addresses this capture by: `<stream>:<digest>`.
    ///
    /// One string rather than two fields at every call site, and the shape
    /// CLOUD-121's `show` and CLOUD-117's predicate both read. A byte range is
    /// appended by the consumer that needs one, never stored here.
    #[must_use]
    pub fn handle(&self) -> String {
        format!("{}:{}", self.stream, self.digest)
    }
}

/// The directory captures live in, under the repository's state root.
fn captures_dir(repo_root: &Path) -> Result<PathBuf> {
    Ok(state::repo_state_dir(repo_root)?.join("captures"))
}

/// Store `bytes` as `stream`'s capture for the repository at `repo_root`.
///
/// Content-addressed and therefore idempotent: storing the same bytes twice
/// leaves one record, and the returned [`Capture`] is identical both times.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be written. **Never a silent skip** — this is the substrate a gate will read,
/// and a capture that quietly did not happen is indistinguishable from a command
/// nobody checked. That is the same posture the receipt store takes, and the
/// reason both are internal errors rather than fail-open allowances.
pub fn store(repo_root: &Path, stream: Stream, bytes: &[u8]) -> Result<Capture> {
    let digest = identity::capture_fingerprint(stream.as_str(), bytes).to_hex();
    let dir = captures_dir(repo_root)?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the capture store {}", dir.display()))?;

    // The digest already carries the stream, so the filename does not need to —
    // but it is included so a human listing the directory can tell what they are
    // looking at without hashing anything.
    let path = dir.join(format!("{}-{digest}", stream.as_str()));
    // Write unconditionally rather than skipping an existing file: a truncated
    // record from an interrupted earlier run would otherwise persist forever
    // under a digest that promises different bytes.
    let mut file = std::fs::File::create(&path)
        .with_context(|| format!("write the capture {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write the capture {}", path.display()))?;

    Ok(Capture {
        stream: stream.as_str(),
        bytes: bytes.len() as u64,
        digest,
    })
}

/// Read back the bytes a [`Capture`] points at.
///
/// The read half CLOUD-117's predicate and CLOUD-121's `show` both need. It is
/// here rather than in either of them for the same reason the write half is: two
/// readers deriving the path independently is two chances to disagree about it.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or the record cannot
/// be read.
pub fn read(repo_root: &Path, capture: &Capture) -> Result<Vec<u8>> {
    let path = captures_dir(repo_root)?.join(format!("{}-{}", capture.stream, capture.digest));
    std::fs::read(&path).with_context(|| format!("read the capture {}", path.display()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn every_stream_round_trips_through_its_token() {
        for stream in Stream::ALL {
            let token = stream.as_str();
            assert!(!token.is_empty());
            assert_eq!(
                Stream::ALL
                    .iter()
                    .filter(|other| other.as_str() == token)
                    .count(),
                1,
                "{token} is declared twice"
            );
        }
    }

    #[test]
    fn a_handle_names_the_stream_and_the_digest() {
        let capture = Capture {
            stream: "stdout",
            bytes: 3,
            digest: "abc".to_owned(),
        };
        assert_eq!(capture.handle(), "stdout:abc");
    }

    #[test]
    fn the_same_bytes_on_two_streams_are_two_identities() {
        // A program that wrote the same text to both streams must not collapse
        // into one record, or a predicate scoped to stderr would match stdout.
        let out = identity::capture_fingerprint(Stream::Stdout.as_str(), b"same");
        let err = identity::capture_fingerprint(Stream::Stderr.as_str(), b"same");
        assert_ne!(out.to_hex(), err.to_hex());
    }

    #[test]
    fn the_digest_is_a_pure_function_of_the_bytes() {
        let first = identity::capture_fingerprint("stdout", b"hello\n");
        let second = identity::capture_fingerprint("stdout", b"hello\n");
        assert_eq!(first.to_hex(), second.to_hex());
        assert_ne!(
            first.to_hex(),
            identity::capture_fingerprint("stdout", b"hello").to_hex(),
            "a trailing newline is a different output, so it is a different capture"
        );
    }

    #[test]
    fn an_empty_stream_still_has_an_identity() {
        // Zero bytes is a real answer — "the command said nothing" — and it must
        // be distinguishable from a run that was never captured.
        let empty = identity::capture_fingerprint("stdout", b"");
        assert_eq!(empty.to_hex().len(), 64);
        assert_ne!(
            empty.to_hex(),
            identity::capture_fingerprint("stderr", b"").to_hex()
        );
    }
}
