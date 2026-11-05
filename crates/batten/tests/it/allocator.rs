//! The global allocator over the compiled binary (CLOUD-2344).
//!
//! `main.rs` gates mimalloc to Linux, and the gate is a `cfg` no unit case can
//! see: a unit test runs in the TEST binary, whose allocator is the platform's.
//! Only the shipped binary can say what it allocates through, and mimalloc says
//! it on request — `MIMALLOC_VERBOSE=1` prints `mimalloc: process init` on
//! stderr when it is linked in, and a binary without it prints nothing.
//!
//! The same case runs on every leg, so under `test:musl` it checks the musl
//! binary `install.sh` ships, which is the arm CLOUD-2344 opened.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::expect_used)]

use crate::common;

use common::{batten, stderr};

#[test]
fn the_linux_binary_allocates_through_mimalloc() {
    let output = batten()
        .arg("--version")
        .env("MIMALLOC_VERBOSE", "1")
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(0));
    let said = stderr(&output);
    assert_eq!(
        said.contains("mimalloc:"),
        cfg!(target_os = "linux"),
        "{said}"
    );
}
