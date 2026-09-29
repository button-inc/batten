//! No `batten` resolvable by name while the suite runs (CLOUD-1951).
//!
//! CI's test job has no `batten` on PATH; this box has two — `target/release`
//! through `_.path` and the installed release in `~/.local/bin`. A case or hook
//! that spawns a bare `batten` therefore passed locally and failed on CI.
//!
//! `test:cargo`'s shell body used to mask the whole suite's PATH, and this tier
//! ran that block verbatim. The body retired to one argv (CLOUD-843), and the mask
//! moved into the harness every case reaches the binary through:
//! `common::batten()` hands its child `common::ambient_path()`. So these cases
//! drive `common::mask_batten` — the function that builds it — directly, over
//! PATHs they construct.
//!
//! THE OTHER HALF OF THAT BODY, CLOUD-1953's before/after comparison of tracked
//! state, moved to `receipt clean`'s predicate after the lap's gates: locally
//! `receipt record`'s refusal at the end of `verify:gated`, on CI the
//! `mise run tree-clean` step after `mise run ci`. Both cover every gate the lap
//! runs rather than this one suite; `receipt_clean.rs` is where the predicate is
//! pinned.

// Its mutations are declared HERE, for the reason `target_prune.rs` gives for its
// own: `test name undefined` reads `crates/batten/tests/**` for the row, and the
// expression belongs to `common/mod.rs`, which is no gate's source — so the rows
// are INERT under the sweep and are applied BY HAND against `common/mod.rs`, the
// named case run, the file restored.
//
// SO NEITHER ROW IS ENFORCED, stated rather than implied by the row syntax:
// `mutate::sources_for` routes a gate name only to `mise-tasks/`, `policy/`, the
// engine, a preset or the task manifest, so no `MUTANT_GATES` entry can reach
// `common/mod.rs` and `mutant-census` counts neither. The narrowed CLOUD-1951
// mask is guarded by a hand application at integration until the sweep grows a
// route to test-support sources.
/*
#MUTANT-SUITE crates/batten/tests/it/test_cargo_path.rs
#MUTANT installed-batten-visible|s@^        if name == "batten" {$@        if name == "not-batten" {@|the_mask_hides_every_batten_and_keeps_the_rest
#MUTANT batten-directory-kept|s@^            let shadow = shadows.join(name);$@            let shadow = dir.clone();@|the_mask_hides_every_batten_and_keeps_the_rest
*/

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

fn stub(dir: &Path, name: &str) {
    fs::create_dir_all(dir).expect("fixture dir");
    let path = dir.join(name);
    fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write stub");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod stub");
    }
}

/// Where a name lookup over `path` finds `name`, or `None`.
///
/// The lookup the shell performs, in process: the first directory in order that
/// holds an entry of that name.
fn resolves(path: &std::ffi::OsStr, name: &str) -> Option<PathBuf> {
    std::env::split_paths(path)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.exists())
}

/// `#MUTANT installed-batten-visible` and `#MUTANT batten-directory-kept` redden
/// here: linking `batten` into the shadow, or keeping its directory, makes it
/// resolvable again.
#[test]
fn the_mask_hides_every_batten_and_keeps_the_rest() {
    if !cfg!(unix) {
        // The shadow is symlinks and the stubs are shebang scripts; off Unix the
        // directory is dropped instead, which hides `batten` as surely and `mise`
        // with it — the cost `common::shadow_of`'s other arm states.
        return;
    }
    let root = common::scratch("test-cargo-path");
    let release = root.join("release");
    let local = root.join("local");
    let other = root.join("other");
    stub(&release, "batten");
    stub(&local, "batten");
    stub(&local, "mise");
    stub(&other, "tool");
    let path = std::env::join_paths([&release, &local, &other]).expect("join the fixture PATH");

    let masked = common::mask_batten(&path, &root.join("shadows"));
    assert_eq!(
        resolves(&masked, "batten"),
        None,
        "no batten resolves by name under the mask"
    );
    assert!(
        resolves(&masked, "mise").is_some(),
        "mise, beside the installed batten, still resolves"
    );
    assert_eq!(
        resolves(&masked, "tool"),
        Some(other.join("tool")),
        "a directory with no batten is left in place"
    );
}

/// A PATH with no `batten` anywhere comes out unchanged.
#[test]
fn a_path_without_batten_is_untouched() {
    let root = common::scratch("test-cargo-path-clean");
    let other = root.join("other");
    stub(&other, "tool");
    let path = std::env::join_paths([&other]).expect("join the fixture PATH");
    assert_eq!(common::mask_batten(&path, &root.join("shadows")), path);
}

/// THE HARNESS HANDS THE MASK TO THE BINARY UNDER TEST, which is what makes it
/// the suite's rather than one tier's: a child the binary starts inherits it.
#[test]
fn the_binary_under_test_is_handed_the_masked_path() {
    let command = common::batten();
    let handed = command
        .get_envs()
        .find(|(name, _)| *name == "PATH")
        .and_then(|(_, value)| value.map(std::ffi::OsStr::to_os_string));
    assert_eq!(handed, Some(common::ambient_path()));
    if cfg!(unix) {
        assert_eq!(
            resolves(&common::ambient_path(), "batten"),
            None,
            "and no batten resolves by name through it"
        );
    }
}
