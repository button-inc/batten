//! `test:cargo`'s PATH mask, run verbatim (CLOUD-1951).
//!
//! CI's test job has no `batten` on PATH; this box has two — `target/release`
//! through `_.path` and the installed release in `~/.local/bin`. A case or hook
//! that spawns a bare `batten` therefore passed locally and failed on CI. The
//! task masks every PATH directory holding one. This tier runs the task's own
//! block, extracted between its markers, so the assertion is over the shipped
//! bytes rather than a copy of them.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};

const OPEN: &str = "# >>> no-batten-path";
const CLOSE: &str = "# <<< no-batten-path";

/// The committed block between the markers.
fn mask() -> String {
    let text = fs::read_to_string(common::at_root("mise.toml")).expect("read mise.toml");
    let start = text.find(OPEN).expect("the opening marker is in mise.toml") + OPEN.len();
    let end = text[start..]
        .find(CLOSE)
        .expect("the closing marker follows it")
        + start;
    text[start..end].to_owned()
}

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

/// What `command -v <name>` resolves to after the mask, one entry per name.
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: the mask is shell the task runs under `sh`, so running it under `sh` is the only reading of the shipped bytes"
)]
fn resolved_after_mask(dirs: &[PathBuf], target: &Path, names: &[&str]) -> Vec<Option<String>> {
    let mut probe = String::new();
    for name in names {
        probe.push_str("command -v ");
        probe.push_str(name);
        probe.push_str(" || echo MISSING\n");
    }
    let out = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(format!("{}\n{probe}", mask()))
        // The system directories stay last, as on any real PATH: the mask itself
        // spawns `rm`, `mkdir` and `ln`.
        .env(
            "PATH",
            std::env::join_paths(
                dirs.iter()
                    .cloned()
                    .chain([PathBuf::from("/usr/bin"), PathBuf::from("/bin")]),
            )
            .expect("join the fixture PATH"),
        )
        .env("CARGO_TARGET_DIR", target)
        .output()
        .expect("run the mask under sh");
    assert!(out.status.success(), "the mask exits 0: {out:?}");
    String::from_utf8(out.stdout)
        .expect("utf-8")
        .lines()
        .map(|line| (line != "MISSING").then(|| line.to_owned()))
        .collect()
}

/// `#MUTANT installed-batten-visible` reddens here: linking `batten` into the
/// shadow makes it resolvable again.
#[test]
fn the_mask_hides_every_batten_and_keeps_the_rest() {
    if !cfg!(unix) {
        // Symlinks and `/bin/sh`: the mask runs inside a mise task, which the
        // windows leg reaches through `cargo nextest` directly, never this body.
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
    let path = [release, local, other.clone()];

    let found = resolved_after_mask(&path, &root.join("target"), &["batten", "mise", "tool"]);
    assert_eq!(found[0], None, "no batten resolves by name under the mask");
    assert!(
        found[1].is_some(),
        "mise, beside the installed batten, still resolves"
    );
    assert_eq!(
        found[2].as_deref(),
        Some(other.join("tool").to_str().expect("utf-8 path")),
        "a directory with no batten is left in place"
    );
}

/// A PATH with no `batten` anywhere comes out unchanged.
#[test]
fn a_path_without_batten_is_untouched() {
    if !cfg!(unix) {
        // As above: symlinks and `/bin/sh`.
        return;
    }
    let root = common::scratch("test-cargo-path-clean");
    let other = root.join("other");
    stub(&other, "tool");
    let found = resolved_after_mask(
        std::slice::from_ref(&other),
        &root.join("target"),
        &["tool"],
    );
    assert_eq!(
        found[0].as_deref(),
        Some(other.join("tool").to_str().expect("utf-8 path"))
    );
}
