//! The capture adapter (`batten::exec::Streamed`, #1276) over real children:
//! `output`'s contract, with every stream pumped as it is written.
//!
//! Here rather than beside the adapter: each case IS a spawn, and the engine's
//! source admits exactly one capture spawn, the adapter itself.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::exec::{Keep, Streamed as _};

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
        reason = "stays: the case IS a spawn, because the adapter's contract is about a real child's pipes"
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
/// file becomes closed, and the child reads nothing), or a stream the caller
/// did not name left without `output`'s default.
#[test]
fn a_kept_stream_is_left_as_the_caller_set_it() {
    if !cfg!(unix) {
        return;
    }
    let dir = crate::common::scratch("exec-streamed-keep");
    let input = dir.join("in");
    std::fs::write(&input, "from the file").unwrap();
    let cat = |keep: Keep| {
        #[expect(
            clippy::disallowed_types,
            reason = "stays: the case IS a spawn, because the adapter's contract is about a real child's pipes"
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
}
