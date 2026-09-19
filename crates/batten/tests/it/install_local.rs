//! The provisioning script supersedes the downloaded consumer artifact with this
//! clone's own build (CLOUD-1859).
//!
//! `deps-install` runs `install.sh`, which resolves `-musl` for every Linux host
//! deliberately — the static binary runs on any Linux whatever its glibc version.
//! That is right for a consumer and wrong for a dev container, because the binary
//! it leaves on PATH is the one every harness hook spawns on every tool call.
//!
//! Measured 2026-09-19, same version, same tree, same box, warm and repeated:
//! `adjudicate` 1444ms against 96ms, `check` over 143 rules 15501ms against
//! 1791ms. `strace -c` on one adjudication: 5779 syscalls against 362, of which
//! 2728 `mmap` and 2718 `munmap` — mallocng returning freed memory to the OS on
//! every free where glibc retains its arenas.
//!
//! THE SUBJECT IS THE CALL, NOT THE BINARY. A test asserting that the installed
//! `batten` is dynamically linked would pass or fail on whatever the machine
//! running the suite happens to have provisioned, which is a property of the host
//! rather than of this repository. What this tree decides is whether its own
//! provisioning script asks for the supersession, and that is what is asserted.

use crate::common;

/// The needle is assembled rather than spelled, because this file is scanned by
/// the same censuses that scan the tree and a literal here is a second site
/// claiming to be the call (`rules/scanning.md`).
fn supersession_call() -> String {
    ["mise run ", "install:local"].concat()
}

/// The predicate, factored out so the anti-vacuity case below drives the same
/// reading the real one does rather than a paraphrase of it.
fn supersedes(script: &str) -> bool {
    script.contains(&supersession_call())
}

fn committed_setup() -> String {
    let path = common::at_root("setup.sh");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("setup.sh should be readable at {}: {e}", path.display()))
}

#[test]
fn setup_supersedes_the_consumer_artifact_with_the_local_build() {
    assert!(
        supersedes(&committed_setup()),
        "setup.sh should invoke the supersession task after deps-install, or every \
         harness hook in a provisioned container spawns the musl consumer artifact"
    );
}

#[test]
fn a_setup_that_never_supersedes_is_refused() {
    // ANTI-VACUITY. Without this, the case above passes over any file that happens
    // to contain the string, and would keep passing if the predicate were widened
    // to something that cannot fail.
    let without = "mise run deps-install || echo 'incomplete' >&2\n";
    assert!(
        !supersedes(without),
        "a provisioning script that never supersedes must be refused by the same \
         reading that accepts the committed one"
    );
}

#[test]
fn the_supersession_runs_after_the_install_it_supersedes() {
    // ORDER IS THE WHOLE OF IT. `install:local` writes to `install.sh`'s own
    // destination, so running it BEFORE `deps-install` would have the download
    // overwrite the local build and leave the slow binary on PATH — green by this
    // file's first case and wrong in the container.
    let script = committed_setup();
    let install = script
        .find(&["mise run ", "deps-install"].concat())
        .expect("setup.sh should run the provisioning install");
    let supersede = script
        .find(&supersession_call())
        .expect("setup.sh should run the supersession");
    assert!(
        supersede > install,
        "the supersession must follow the install it supersedes, or the download \
         overwrites the local build"
    );
}
