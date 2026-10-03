//! A bare `Path::canonicalize` in the engine is held to its counted ceiling
//! (CLOUD-2059).
//!
//! On Windows `canonicalize` answers in the VERBATIM spelling, `\\?\D:\…`, while
//! every root `batten::git` resolves is spelled plain (`git::canonical`). A
//! verbatim path shares no prefix with a plain one, so comparing across the two
//! reads every path as outside the other. Measured twice:
//!
//! - `receipt::judgeable` allowed every write on Windows;
//! - `testing::falls_through` read every owned fixture as falling through and
//!   refused 2,614 cases on the Windows leg of #1089.
//!
//! Neither shows on the platform a contributor runs, so the class is refused
//! HERE, where it is free to catch. New code spells `git::canonical`, and a
//! file's bare calls may only fall. Comment lines are not code, so a doc or a
//! `//MUTANT` row naming the call does not count.

use std::collections::BTreeMap;
use std::path::Path;

use crate::common;

/// The bare calls each engine file carried when this ratchet was set. A file
/// absent here may carry none.
const CEILINGS: &[(&str, usize)] = &[
    ("crates/batten/src/admission.rs", 1),
    ("crates/batten/src/git.rs", 3),
    ("crates/batten/src/hook.rs", 3),
    ("crates/batten/src/lib.rs", 5),
    ("crates/batten/src/perf.rs", 5),
    ("crates/batten/src/secrets.rs", 2),
    ("crates/batten/src/semver.rs", 2),
    ("crates/batten/src/wiring.rs", 2),
];

/// The call this ratchet counts.
const NEEDLE: &str = ".canonicalize()";

/// Bare calls per tracked engine source under `root`, comment lines excluded.
fn bare_calls(root: &Path) -> BTreeMap<String, usize> {
    let tracked = batten::git::tracked_paths(root).expect("the tracked set");
    let mut counts = BTreeMap::new();
    let sources = tracked.iter().filter(|path| {
        path.starts_with("crates/batten/src/")
            && Path::new(path).extension().is_some_and(|ext| ext == "rs")
    });
    for path in sources {
        let text = std::fs::read_to_string(root.join(path)).expect("read a tracked source");
        let calls: usize = text
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .map(|line| line.matches(NEEDLE).count())
            .sum();
        if calls > 0 {
            counts.insert(path.clone(), calls);
        }
    }
    counts
}

/// Every engine file is at its ceiling: above it is a new bare call, below it is
/// a ceiling to lower so the fall is kept.
#[test]
fn no_engine_file_adds_a_bare_canonicalize() {
    let found = bare_calls(&common::at_root("."));
    let ceilings: BTreeMap<&str, usize> = CEILINGS.iter().copied().collect();
    for (path, calls) in &found {
        let ceiling = ceilings.get(path.as_str()).copied().unwrap_or(0);
        assert!(
            *calls <= ceiling,
            "{path} carries {calls} bare `{NEEDLE}`, above its ceiling of {ceiling}: spell \
             `batten::git::canonical`, whose plain spelling compares with every root the \
             engine resolves"
        );
    }
    for (path, ceiling) in &ceilings {
        let calls = found.get(*path).copied().unwrap_or(0);
        assert_eq!(
            calls, *ceiling,
            "{path} now carries {calls} bare `{NEEDLE}`, under its ceiling of {ceiling}: \
             lower the ceiling in this file so the fall is kept"
        );
    }
}

/// THE ANTI-VACUITY ARM: the census reads the tree it judges. A counter that
/// found nothing would pass the case above whatever the engine spelled, so the
/// one file known to carry calls must be seen carrying them.
#[test]
fn the_census_sees_the_calls_it_ratchets() {
    let found = bare_calls(&common::at_root("."));
    assert!(
        found
            .get("crates/batten/src/git.rs")
            .is_some_and(|calls| *calls > 0),
        "the census read no bare `{NEEDLE}` in git.rs, so it reads nothing: {found:?}"
    );
}
