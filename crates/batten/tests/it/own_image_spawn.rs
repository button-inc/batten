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

use std::path::{Path, PathBuf};

use common::{Fixture, StateHome, batten, scratch};

/// The exit code the decoy answers with — distinct from anything the engine
/// itself returns for `--version`, so a passing run cannot be the decoy's.
const DECOY_CODE: i32 = 17;

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
    use std::os::unix::fs::PermissionsExt;
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
    let home = Fixture::at(root.join("home")).build();

    // The decoy first, then the system directories the decoy's own `#!/bin/sh`
    // needs. Nothing else: an ambient `batten` on the developer's `PATH` would
    // make the decoy unreachable and the case vacuous.
    let path = format!("{}:/usr/bin:/bin", decoy.display());
    let output = batten()
        .state_home(&home)
        .args(&["enforce"])
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
