//! A declared `batten` runs the image that asked, over the compiled engine
//! (CLOUD-2386).
//!
//! # Why this tier, and not `rules.rs`'s own cases
//!
//! `a_declared_batten_resolves_to_the_running_image_before_the_pin` proves rung
//! -1 decides correctly, but it calls `spawn_resolving_on_image` and hands it a
//! `running` of its own. Nothing in that suite reads the WIRING — that
//! `spawn_resolving` computes the image at all and passes it down. Mutating
//! that one expression to `None` reverts every declared `batten` row to a
//! `PATH` lookup, which is precisely the skew CLOUD-2386 exists to close, and
//! the whole library suite stays green: a unit test cannot tell the running
//! image apart from a `batten` on `PATH`, because in-process they are the same
//! file. Only a child spawned from a `PATH` the case controls can.
//!
//! So the discriminator is a decoy. A directory whose only `batten` is a script
//! that fails goes on the front of `PATH`, and a `command` row names the bare
//! word `batten`. The running image answers `--version` with exit 0 and the
//! rule passes; the decoy answers with 17 and the rule is a violation. The two
//! outcomes are different exit codes from `enforce`, so the case cannot pass
//! for the wrong reason.
//!
//! `enforce` rather than `check`, because `check` is a read verb by contract
//! and refuses a rule kind that spawns at all (`extension_surfaces.rs`).
//!
//! # Unix only, and registered that way
//!
//! The decoy is a `#!/bin/sh` script whose permission bits are the mechanism,
//! so `PermissionsExt` does not compile off Unix at all. That is `rules/rust.md`'s
//! stated exception to the `cfg!`-inside-a-case rule — the case reaches a symbol
//! the other target does not have — so `main.rs` gates the whole module, as it
//! already does for `ntia`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::{Fixture, StateHome, batten, scratch};

/// The exit code the decoy answers with — distinct from anything the engine
/// itself returns for `--version`, so a passing run cannot be the decoy's.
const DECOY_CODE: i32 = 17;

/// A repository with one `command` row naming the bare word `batten`, and a
/// state home beside it.
fn self_image_repo(root: &Path) -> (PathBuf, PathBuf) {
    let repo = Fixture::at(root.join("repo"))
        .config(
            "version = 1\n\n\
             [[rule]]\n\
             id = \"self-image\"\n\
             kind = \"command\"\n\
             glob = \"**/*.rs\"\n\
             check = \"batten --version\"\n\
             severity = \"deny\"\n",
        )
        .file("lib.rs", "fine\n")
        .git()
        .base_commit()
        .build();
    (repo, Fixture::at(root.join("home")).build())
}

/// A directory whose only `batten` is a script that exits [`DECOY_CODE`].
///
/// Executable on purpose. A decoy that could not run would turn a broken rung
/// into `NotFound`, which is also non-zero — the case would still fail, but for
/// "nothing ran" rather than for "the wrong thing ran", and the second is the
/// defect under test.
fn decoy_dir(root: &Path) -> PathBuf {
    let dir = root.join("decoy");
    std::fs::create_dir_all(&dir).expect("the decoy directory is creatable");
    let decoy = dir.join("batten");
    std::fs::write(&decoy, format!("#!/bin/sh\nexit {DECOY_CODE}\n"))
        .expect("the decoy is written");
    std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o755))
        .expect("the decoy is executable");
    dir
}

/// A declared `batten` reaches the running engine, not whatever `PATH` holds.
///
/// **This is the wiring case.** Reverting `spawn_resolving`'s `running` to
/// `None`, or dropping the argument it passes, leaves every rung -1 unit
/// assertion green and fails here.
#[test]
fn a_command_row_naming_batten_runs_the_image_and_not_the_one_on_path() {
    let root = scratch("own-image-spawn");
    let decoy = decoy_dir(&root);
    let (repo, home) = self_image_repo(&root);

    // The decoy first, then `common::ambient_path`: the ambient `PATH` with every
    // `batten` shadowed out, so no real `batten` sits behind the decoy and makes
    // the case vacuous. `join_paths`, never an interpolated `:` (`primitives.rs`).
    let ambient = common::ambient_path();
    let path = std::env::join_paths(std::iter::once(decoy).chain(std::env::split_paths(&ambient)))
        .expect("the decoy PATH composes");
    let output = batten()
        .state_home(&home)
        .args(["enforce"])
        .current_dir(&repo)
        .env("PATH", &path)
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten");
    let code = output.status.code().expect("exit code");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_ne!(
        code, 2,
        "the decoy ran: a declared `batten` resolved on `PATH` instead of to the \
         running image, which is CLOUD-2386's defect. stderr: {stderr}"
    );
    assert_eq!(
        code, 0,
        "the running image answered `--version` and the row passed. stderr: {stderr}"
    );
}

/// `doctor` agrees with the spawn: a `command` row naming `batten` reads as
/// reachable on a `PATH` that carries no `batten` at all.
///
/// **The arm the unit tier cannot decide.** `doctor::command_program_resolves`
/// ORs the image, `PATH` and the pin, and under `cargo test` the checkout's own
/// build is on `PATH` — so in-process the `PATH` arm answers for `batten` too
/// and negating the image arm changes nothing any unit case can see. Every
/// mutant of that predicate survived for exactly that reason. Here the `PATH`
/// is the case's own and holds no `batten`, so the image arm is the only thing
/// that can resolve the row.
#[test]
fn doctor_reads_a_command_row_naming_batten_as_reachable_without_it_on_path() {
    let root = scratch("own-image-doctor");
    let (repo, home) = self_image_repo(&root);

    let output = batten()
        .state_home(&home)
        .args(["doctor"])
        .current_dir(&repo)
        .env("PATH", common::ambient_path())
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .output()
        .expect("run batten doctor");
    // Concatenated rather than `format!`ed: `every_path_override_is_composed_with_join_paths`
    // reads a `format!` beside a `PATH` override as a separator spelled by hand.
    let mut report = String::from_utf8_lossy(&output.stdout).into_owned();
    report.push_str(&String::from_utf8_lossy(&output.stderr));

    assert!(
        !report.contains("program-not-on-path"),
        "`batten` is what rung -1 spawns, so the probe must not ask PATH for it: {report}"
    );
}
