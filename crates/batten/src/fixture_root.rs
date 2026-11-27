//! The lib cases' own root (CLOUD-2904, D3): a fresh empty directory OUTSIDE
//! this checkout, so a case handed it answers about its fixture and never about
//! whichever repository the test process stands in. `Path::new(".")` in a lib
//! case is the cwd, and the cwd of `cargo test` is the crate inside the
//! checkout, so discovery from it reads the checkout's `.git`.

use std::path::PathBuf;

/// A new, empty directory under the system temp dir, unique to `name` and this
/// process, never inside a repository.
///
/// # Panics
///
/// When the directory cannot be created: setup failing is the case failing.
#[must_use]
#[expect(
    clippy::expect_used,
    reason = "test setup: failing loudly is the point"
)]
pub(crate) fn fixture_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "batten-lib-root-{name}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(&dir).expect("create the fixture root");
    dir
}
