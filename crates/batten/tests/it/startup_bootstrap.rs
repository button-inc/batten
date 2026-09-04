//! The bootstrap half of `[[startup]]`, over the compiled binary (CLOUD-1389).
//!
//! # What this tier reaches that `startup.rs` and `provision.rs` cannot
//!
//! `startup.rs` proves the verb carries rows and renders them; `provision.rs`
//! proves an entry fetches, verifies and caches. Neither reaches the property the
//! one-line Setup script actually depends on: that a provisioned binary lands
//! somewhere a LATER ROW can invoke by bare name.
//!
//! That is the failure mode with no symptom. `link` writing nothing leaves the
//! cache correct, `provision apply` exiting 0, and `batten startup` reporting
//! every row — while `mise` is not on `PATH` and the container has no way to run
//! a gate. A unit case over `install` would assert the cache write and pass.
//!
//! # The ordering case, and why it is not decoration
//!
//! `toolchain-runner-present` must precede the rows whose `check` and `repair`
//! INVOKE the runner. Reordered, those rows' checks fail to spawn on a cold
//! container — and a check that cannot spawn is could-not-look, which
//! `startup.rs` already pins as distinct from a failure. So the set would report
//! a shape a reader cannot act on, at an exit code that looks like a verdict.
//! Declaration order is running order, so the order IS the mechanism and nothing
//! else asserts it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use common::{batten, init_repo, scratch, stderr, stdout, write};

/// The repository root, whose committed `batten.toml` is under test.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// The committed authority, which is what these cases are about.
///
/// Read rather than restated: a fixture spelling its own rows would assert that
/// the FIXTURE is ordered, which is the tautology this file exists to avoid.
fn committed() -> String {
    std::fs::read_to_string(root().join("batten.toml")).expect("the authority is readable")
}

/// The `[[startup]]` row ids the committed config declares, in declaration order.
fn declared_rows() -> Vec<String> {
    let text = committed();
    let mut ids = Vec::new();
    let mut in_row = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed == "[[startup]]" {
            in_row = true;
            continue;
        }
        if trimmed.starts_with("[[") || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
            in_row = false;
        }
        if in_row && let Some(rest) = trimmed.strip_prefix("id = ") {
            ids.push(rest.trim_matches('"').to_string());
            in_row = false;
        }
    }
    ids
}

#[test]
fn the_runner_row_precedes_every_row_that_invokes_the_runner() {
    let rows = declared_rows();
    let runner = rows
        .iter()
        .position(|id| id == "toolchain-runner-present")
        .expect("the committed config declares the runner bootstrap row");
    for dependent in ["toolchain-is-provisioned", "host-dependencies-present"] {
        let at = rows
            .iter()
            .position(|id| id == dependent)
            .unwrap_or_else(|| panic!("the committed config declares {dependent}"));
        assert!(
            runner < at,
            "{dependent} invokes the runner, so it must be declared after \
             toolchain-runner-present puts it on PATH — declaration order is \
             running order. Order was {rows:?}"
        );
    }
}

#[test]
fn the_runner_check_is_answerable_with_only_batten_present() {
    // THE CASE THAT WOULD HAVE CAUGHT THE COMMITTED DEFECT. The first version of
    // this row checked `["mise", "--version"]`, which cannot spawn on the one
    // container the row is for — and `startup.rs` reports an unspawnable check as
    // could-not-look and never repairs on one, so the row was dead exactly where
    // it mattered while reporting `ok` on every provisioned machine.
    //
    // Asserted over the PROGRAM rather than the whole argv: which subcommand
    // answers the freshness question may change, but it must stay a question
    // batten can answer, because batten is the only thing the Setup script
    // guarantees is installed.
    let text = committed();
    let row = text
        .split("[[startup]]")
        .find(|block| block.contains("id = \"toolchain-runner-present\""))
        .expect("the runner bootstrap row is declared");
    let check = row
        .lines()
        .find_map(|line| line.trim().strip_prefix("check = "))
        .expect("the row declares a check");
    assert!(
        check.starts_with(r#"["batten""#),
        "the runner row's check must be answerable by batten alone — the runner it \
         is about is what may be missing, and a check that cannot spawn is \
         reported as could-not-look and never repaired. Was: {check}"
    );
}

#[test]
fn the_runner_row_repairs_through_provision_rather_than_a_shell() {
    // The discriminating assertion, not a spelling preference. `check`/`repair`
    // are argv with no shell between them and what runs, so a `curl … | sh`
    // repair is unexpressible — and a row that tried would be one word naming a
    // program that does not exist. Pinning the declared repair is what keeps a
    // later author from "fixing" that by adding a shell wrapper.
    let text = committed();
    let row = text
        .split("[[startup]]")
        .find(|block| block.contains("id = \"toolchain-runner-present\""))
        .expect("the runner bootstrap row is declared");
    assert!(
        row.contains(r#"repair = ["batten", "provision", "apply"]"#),
        "the runner is provisioned by a pinned, checksum-verified entry rather \
         than a fetched script"
    );
}

#[test]
fn the_runner_entry_is_the_only_provision_row_carrying_a_link() {
    // `link` widens what a consumer's shell can reach, so it is the bootstrap
    // entry's alone. A second row growing one is a decision somebody should have
    // to make deliberately, and this is what makes them.
    let text = committed();
    let linked: Vec<&str> = text
        .split("[[provision]]")
        .skip(1)
        .filter(|block| block.contains("link = "))
        .filter_map(|block| {
            block
                .lines()
                .find_map(|line| line.trim().strip_prefix("name = "))
        })
        .collect();
    assert_eq!(
        linked,
        vec!["\"mise\""],
        "only the task runner needs PATH presence; batten resolves every other \
         provisioned binary from its own cache"
    );
}

/// A repository declaring one provision entry that links into `dest`.
fn linked_fixture(name: &str, dest: &str, body: &[u8]) -> (PathBuf, PathBuf) {
    let dir = scratch(name);
    let artifact = dir.join("artifact.bin");
    std::fs::create_dir_all(&dir).expect("the scratch directory exists");
    std::fs::write(&artifact, body).expect("the artifact is written");
    let digest = sha256_hex(body);
    // TOML LITERAL STRINGS for the two path-bearing fields, and on Windows that
    // is a correctness requirement rather than a style. A native path is
    // `D:\a\...`, and a backslash inside a BASIC string is an escape — so
    // `url = "file://D:\a\..."` is `missing escaped value, expected b, e, f, n,
    // r, \, ", x, u, U` and the config does not load. Measured on the windows
    // runner, both link cases, while every unix arm passed.
    //
    // Literal rather than escaped: `provision::fetch` strips `file://` and reads
    // the remainder as a path verbatim, so a native Windows path is what it
    // wants — doubling the separators would build a path nothing can open, and
    // rewriting them to `/` would test a spelling no consumer writes.
    write(
        &dir,
        "batten.toml",
        &format!(
            "version = 1\n\n[[provision]]\nname = \"probe\"\nversion = \"1\"\n\
             url = 'file://{}'\nsha256 = \"{digest}\"\nunpack = \"none\"\n\
             binary = \"probe\"\nlink = '{dest}'\n",
            artifact.display()
        ),
    );
    write(&dir, "a.txt", "x\n");
    // `init_repo`, never a `git init` fork: main's fixture-fork ratchet
    // (`fixture-fork-added`) refuses the fork, and under `CARGO_TARGET_TMPDIR`
    // this copies the published template at zero forks instead.
    init_repo(&dir);
    (dir, artifact)
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .fold(String::new(), |mut hex, byte| {
            // `write!` into one buffer rather than a `format!` per byte, which
            // `clippy::format_collect` refuses: 32 allocations for a 64-character
            // string.
            let _ = write!(hex, "{byte:02x}");
            hex
        })
}

#[test]
fn applying_a_linked_entry_puts_the_binary_where_a_bare_name_resolves() {
    let dest = scratch("provision-link-dest");
    std::fs::create_dir_all(&dest).expect("the destination exists");
    // Removed first: a previous failing run strands the copy, and a case that
    // asserted presence over that residue would pass with the feature deleted.
    let landed = dest.join("probe");
    let _ = std::fs::remove_file(&landed);
    let (dir, _artifact) = linked_fixture(
        "provision-link",
        dest.to_str().expect("the scratch path is UTF-8"),
        b"#!/bin/sh\nexit 0\n",
    );
    let out = batten()
        .current_dir(&dir)
        .args(["provision", "apply"])
        .output()
        .expect("the binary runs");
    assert_eq!(
        out.status.code(),
        Some(0),
        "apply should succeed: {}",
        stderr(&out)
    );
    assert!(
        landed.is_file(),
        "the declared link destination should carry the binary, so a later row \
         can invoke it by bare name; stdout was {}",
        stdout(&out)
    );
    assert!(
        is_executable(&landed),
        "a binary on PATH that is not executable is the same dead bootstrap one \
         layer down"
    );
}

#[test]
fn a_warm_cache_whose_link_vanished_is_relinked_rather_than_reported_fresh() {
    // THE DEFECT THIS FILE'S FIRST VERSION SHIPPED, and it needed two runs to
    // show: `apply` returns `AlreadyFresh` before reaching `install`, so once the
    // cache was warm the link was never made again. A container keeping its cache
    // and losing `~/.local/bin` would then have `provision status` report `fresh`,
    // `toolchain-runner-present` report `ok`, and no runner on PATH.
    let dest = scratch("provision-relink-dest");
    std::fs::create_dir_all(&dest).expect("the destination exists");
    let (dir, _artifact) = linked_fixture(
        "provision-relink",
        dest.to_str().expect("the scratch path is UTF-8"),
        b"#!/bin/sh\nexit 0\n",
    );
    let landed = dest.join("probe");

    // First apply: cold cache, so this is the path that already worked.
    let first = batten()
        .current_dir(&dir)
        .args(["provision", "apply"])
        .output()
        .expect("the binary runs");
    assert_eq!(first.status.code(), Some(0), "{}", stderr(&first));
    assert!(landed.is_file(), "the cold apply links");

    // Now the link is gone and the cache is not. This is the state a second
    // container boot arrives in.
    std::fs::remove_file(&landed).expect("the link is removed");
    let status = batten()
        .current_dir(&dir)
        .args(["provision", "status"])
        .output()
        .expect("the binary runs");
    assert_ne!(
        status.status.code(),
        Some(0),
        "status is the startup row's own check, so a missing link must read as \
         stale — reporting fresh here is what makes the repair never run: {}",
        stdout(&status)
    );

    let second = batten()
        .current_dir(&dir)
        .args(["provision", "apply"])
        .output()
        .expect("the binary runs");
    assert_eq!(second.status.code(), Some(0), "{}", stderr(&second));
    assert!(
        landed.is_file(),
        "the second apply must restore the link from the cache it already has"
    );
}

#[test]
fn a_relative_link_destination_is_refused_rather_than_resolved() {
    // The direction a miss must fail in. Resolved against the process's own
    // directory, the same manifest would install to different places depending
    // on who ran it — a PATH entry nobody can predict, which is worse than none.
    let (dir, _artifact) = linked_fixture("provision-link-relative", "bin", b"x\n");
    let out = batten()
        .current_dir(&dir)
        .args(["provision", "apply"])
        .output()
        .expect("the binary runs");
    assert_ne!(out.status.code(), Some(0));
    let said = format!("{}{}", stdout(&out), stderr(&out));
    assert!(
        said.contains("relative"),
        "the refusal should name the problem so an author can fix the row: {said}"
    );
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|meta| meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}
