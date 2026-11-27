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
//! file's bare calls may only fall. Comment lines are not code, so a doc
//! naming the call does not count.

use std::collections::BTreeMap;
use std::path::Path;

use crate::common;

/// The bare calls each engine file carried when this ratchet was set. A file
/// absent here may carry none.
///
/// `batten-fsio`'s two are `wiring`'s two, MOVED with `same_file` (CLOUD-2789):
/// the split put the comparison in the leaf, which reaches no `git::canonical`,
/// and both sides canonicalize the same way and meet only each other. The row
/// left `wiring` with them, so neither file can grow a call the other gave up.
const CEILINGS: &[(&str, usize)] = &[
    ("crates/batten/src/admission.rs", 1),
    ("crates/batten-fsio/src/lib.rs", 2),
    ("crates/batten-core/src/git.rs", 3),
    ("crates/batten/src/hook.rs", 3),
    ("crates/batten/src/lib.rs", 5),
    ("crates/batten/src/perf.rs", 5),
    ("crates/batten/src/secrets.rs", 2),
    ("crates/batten/src/semver.rs", 2),
];

/// The call this ratchet counts, as a reader spells it.
const NEEDLE: &str = ".canonicalize()";

/// Bare calls per tracked engine source under `root`, read off the one lossless
/// parse: a method call named `canonicalize` with no argument. A comment, a
/// string or a doc example spelling the call is a token, not a call, so it is
/// never counted — the text scan this replaced counted all three.
///
/// Every crate of the workspace is read: the split (CLOUD-2789) moved `git.rs`
/// into `batten-core`, and a walk of `crates/batten/src` alone stopped seeing
/// the one file [`the_census_sees_the_calls_it_ratchets`] names.
fn bare_calls(root: &Path) -> BTreeMap<String, usize> {
    use ra_ap_syntax::{AstNode as _, ast, ast::HasArgList as _};

    let tracked = batten::git::tracked_paths(root).expect("the tracked set");
    let mut counts = BTreeMap::new();
    let sources = tracked.iter().filter(|path| {
        path.starts_with("crates/")
            && path.contains("/src/")
            && Path::new(path).extension().is_some_and(|ext| ext == "rs")
    });
    for path in sources {
        let text = std::fs::read_to_string(root.join(path)).expect("read a tracked source");
        let batten_facts::facts::Look::Is(file) =
            batten_facts::source::rust_tree(&text, ra_ap_syntax::Edition::Edition2024)
        else {
            panic!("{path} did not parse: an unread file is could-not-look, never zero calls");
        };
        let calls = file
            .syntax()
            .descendants()
            .filter_map(ast::MethodCallExpr::cast)
            .filter(|call| {
                call.name_ref()
                    .is_some_and(|name| name.text() == "canonicalize")
                    && call
                        .arg_list()
                        .is_some_and(|args| args.args().next().is_none())
            })
            .count();
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
            .get("crates/batten-core/src/git.rs")
            .is_some_and(|calls| *calls > 0),
        "the census read no bare `{NEEDLE}` in git.rs, so it reads nothing: {found:?}"
    );
}
