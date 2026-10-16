//! Provisioning leaves the hook on the pinned release (CLOUD-2398), retiring
//! CLOUD-1859's supersession.
//!
//! `setup.sh` used to run `install:local` after `deps-install`, putting this
//! clone's own build where every harness hook resolves `batten`. The reason was
//! measured — `install.sh` then resolved `-musl` on every Linux host, and musl
//! adjudicated 15.0x slower (1444ms against 96ms) — and the cost was not: the
//! build reported the release's version, so a release pin could not tell the
//! hook's engine from the release it names. The bootstrap now resolves `-gnu`
//! on a glibc host, which keeps the measured speed without the build.
//!
//! THE SUBJECT IS THE SCRIPT, NOT THE BINARY, for CLOUD-1859's reason: what a
//! machine happens to have installed is a property of the host. What this tree
//! decides is what its provisioning asks for and what its bootstrap resolves.

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
    script
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .any(|line| line.contains(&supersession_call()))
}

fn committed(name: &str) -> String {
    let path = common::at_root(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{name} should be readable at {}: {e}", path.display()))
}

#[test]
fn setup_never_switches_the_hook_to_the_trees_build() {
    assert!(
        !supersedes(&committed("setup.sh")),
        "setup.sh must not run the local install: it switches the worktree to the tree's \
         build, and the hook would then mediate with an engine no pin names"
    );
}

#[test]
fn a_setup_that_supersedes_is_refused() {
    // ANTI-VACUITY. Without this, the case above passes over a predicate that
    // can never fire.
    let with = format!("mise run deps-install\n{} || true\n", supersession_call());
    assert!(
        supersedes(&with),
        "a provisioning script that supersedes must be refused by the same reading"
    );
}

#[test]
fn the_bootstrap_resolves_gnu_unless_a_musl_loader_is_present() {
    // CLOUD-1859's MEASURED SPEED, KEPT BY THE BOOTSTRAP: glibc is the default
    // and musl is chosen only on the evidence of its loader.
    let script = committed("install.sh");
    let default = script
        .find("libc=gnu")
        .expect("install.sh defaults to the gnu artifact");
    let probe = script
        .find("/lib/ld-musl-*")
        .expect("install.sh switches to musl only on a musl loader");
    assert!(default < probe, "gnu first, musl on evidence: {script}");
}
