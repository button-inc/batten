//! The landing-path half of CLOUD-112: replay the checked-in fuzz corpus.
//!
//! Fuzzing splits into two things that are easy to confuse, and this repo has
//! already drawn the line once — `lock-check`'s split (see
//! `.claude/rules/toolchain.md`): **a property of the commit belongs in the
//! gate, a property of the world belongs on a clock.**
//!
//! * The *search* — `mise run fuzz`, driven by libFuzzer under nightly — is a
//!   property of the world. It is nondeterministic, and a green run proves only
//!   that this seed found nothing this time. It runs on a schedule
//!   (`.github/workflows/fuzz.yml`), never on the landing path, where it would
//!   also make every local `verify` need a nightly toolchain to satisfy
//!   `ci-local-parity`.
//! * The *replay* — this file — is a property of the commit: every input ever
//!   found interesting or crashing still satisfies every property, on this
//!   exact tree, deterministically, in milliseconds. This is what makes "a
//!   reproducer becomes a regression test" structural rather than a habit
//!   somebody has to remember.
//!
//! The properties themselves are NOT restated here. `fuzz/properties.rs` is
//! included verbatim by this file and by both fuzz targets, so a saved
//! reproducer means the same thing in the gate that it meant when the fuzzer
//! found it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]
// `fuzz/properties.rs` is `include!`d below and is SHARED with the `fuzz` crate,
// where its entry points must be `pub` for libFuzzer to reach them. Standalone
// this file was a crate root, so those items were reachable; inside the one
// grouped target (CLOUD-1210) it is a module, and they are not. The allowance
// belongs here rather than in the shared file, which cannot narrow them.
//
// `expect` rather than `allow`, per the workspace's own `unfulfilled_lint_expectations
// = "deny"`: if the include ever stops producing unreachable `pub` items, this
// line is red rather than quietly stale.
#![expect(
    unreachable_pub,
    reason = "the included fuzz properties are `pub` for the `fuzz` crate's libFuzzer entry points, and this file is a module rather than a crate root since CLOUD-1210"
)]

use std::fs;
use std::path::{Path, PathBuf};

include!("../../../../fuzz/properties.rs");

/// The fuzz tree, from this crate's manifest rather than `file!()` — the same
/// resolution `tests/acceptance_corpus.rs` documents.
fn fuzz_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz")
}

/// Every file under `dir`, recursively, in a stable order.
///
/// Absent is not empty: a target with no artifacts yet has no `artifacts/<name>`
/// directory at all, and that is the ordinary state, distinct from a corpus that
/// went missing. The caller decides which of the two it will tolerate.
fn inputs(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        let Ok(entries) = fs::read_dir(&next) else {
            continue;
        };
        for entry in entries {
            let path = entry.expect("read a corpus entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.file_name().and_then(|name| name.to_str()) != Some("README.md") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// One target's property body, named so the table below reads as a table.
type Exercise = fn(&[u8]);

#[test]
fn every_corpus_input_still_satisfies_every_property() {
    // Named per target so a failure names the surface, and so a corpus that
    // emptied for one target cannot hide behind the other's count.
    let targets: [(&str, Exercise); 2] = [
        ("hook_decode", exercise_hook_decode),
        ("config_parse", exercise_config_parse),
    ];

    let fuzz = fuzz_dir();
    for (target, exercise) in targets {
        let seeds = inputs(&fuzz.join("corpus").join(target));
        let crashes = inputs(&fuzz.join("artifacts").join(target));

        // A REPLAY THAT READ NOTHING MUST NOT REPORT GREEN (CLOUD-189, and
        // CLOUD-249 one layer up). The seed corpus is checked in, so an empty
        // one is not "nothing to do" — it is the gate having lost its subject,
        // which is indistinguishable from a pass unless it is asserted.
        assert!(
            !seeds.is_empty(),
            "no seed corpus for {target}: fuzz/corpus/{target}/ is empty or missing, so this \
             gate would pass without replaying anything"
        );

        for input in seeds.iter().chain(crashes.iter()) {
            let data = fs::read(input).expect("read a corpus input");
            // The path is the pointer a failure needs, and a panic inside
            // `exercise` carries only its own message — so name the file first.
            // Cheap enough to do unconditionally: the corpus is small by
            // construction, and libFuzzer's own minimization keeps it that way.
            let replay = std::panic::catch_unwind(|| exercise(&data));
            assert!(
                replay.is_ok(),
                "{}: a checked-in corpus input no longer satisfies the {target} properties",
                input.display()
            );
        }
    }
}
