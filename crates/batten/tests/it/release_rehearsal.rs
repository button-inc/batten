//! THE RELEASE REHEARSAL (CLOUD-2515): the tree, one release ahead.
//!
//! The release PR changes what no feature PR does: release-plz moves the
//! workspace version through `Cargo.toml`, `Cargo.lock` and the changelog, and
//! its pin-move step (`release-plz.yml`, "Move the engine pin") moves
//! `batten.toml`'s `engine` line to `v<version>`. A rule whose verdict depends on
//! any of those is therefore evaluated, for the first time, on the release PR
//! itself, and a head that may touch nothing but the release paths
//! (`release_path::RELEASE_PATHS`) can fix nothing it finds. That is how
//! `ci-parity`'s freeze arm held v0.0.217 red by construction for nine days.
//!
//! This case makes that release PR's state an ordinary PR's question. It copies
//! the tracked tree, moves the manifest, the lock and the pin to the next patch
//! release through `release_state::bump` (the crate's writer for those moves),
//! and runs every row that could read them, so a rule only the release PR would
//! trip fails here first, on the change that introduced it.
//!
//! THE CHANGELOG IS NOT MOVED, and that is a fidelity choice. `bump` renames
//! the `## [X]` heading, where release-plz adds a `## [X+1]` section above it, so
//! writing `bump`'s changelog would rehearse a tree no release PR has. No row
//! names the changelog today; one that does owes this case a release-plz-shaped
//! changelog move first.
//!
//! # Which rows
//!
//! A `policy` row on the `tree` scope, with a `module`, no `base`, that names a
//! moved path literally among its `sources`, `documents` or `line_sources`. Each
//! exclusion is a property rather than an id:
//!
//! * a preset row has no `module`, and reads the binary's vendored text;
//! * a `base` row asks git history, which a scratch copy does not carry and the
//!   moves do not change.
//!
//! # Why `RunOverSelection`
//!
//! The selection is partial, so the registry-exhaustion check a full load makes
//! (every declared verdict raised by some loaded module) would refuse it before
//! any rule ran. `RunOverSelection` is the narrowed caller's entitlement.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use batten::release_state::{self, Files};
use batten::rules::{self, RuleKind, RuleScope};

use crate::common;

/// The release paths this case moves, as they appear in a row's declarations.
const MOVED: [&str; 3] = ["Cargo.toml", "Cargo.lock", "batten.toml"];

/// Every tracked file of the checkout at `root`, copied under `scratch`.
fn copy_tracked(root: &Path, scratch: &Path) {
    // From the index, unquoted: plain `ls-files` C-quotes a path with unusual
    // bytes, which would read as missing below and drop out unseen.
    for path in batten::git::tracked_paths(root).expect("the tracked set") {
        let to = scratch.join(&path);
        fs::create_dir_all(to.parent().expect("a tracked file has a parent")).expect("scratch dir");
        match fs::copy(root.join(&path), &to) {
            Ok(_) => {}
            // A tracked path deleted in the working tree is not part of the
            // tree a rule reads, so it is not part of the rehearsal either.
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => panic!("copy {path} into the rehearsal: {error}"),
        }
    }
}

/// Move the copy's manifest, lock and pin to the next patch release, and return
/// the version.
fn move_to_next_release(scratch: &Path) -> String {
    let read = |path: &str| fs::read_to_string(scratch.join(path)).expect("a release path");
    let write = |path: &str, text: &str| {
        fs::write(scratch.join(path), text).expect("write a moved release path");
    };
    let manifest = read("Cargo.toml");
    let current = batten::release_path::version_of(&manifest).expect("a workspace version");
    // `main` pins the release it carries; a working tree pinned to a source
    // build (`install:local`) is put back to that before the move.
    let pinned = batten::engine::Pin {
        release: Some(format!("v{current}")),
        source: None,
    };
    let files = Files {
        manifest,
        lock: read("Cargo.lock"),
        config: batten::engine::rewrite(&read("batten.toml"), &pinned),
        // Read because `bump` requires its heading; never written (above).
        changelog: read("crates/batten/CHANGELOG.md"),
    };
    let packages = release_state::workspace_packages(&files.lock);
    let (next, moved) = release_state::bump(&files, &current, &packages)
        .unwrap_or_else(|why| panic!("the release paths move as a release moves them: {why}"));
    write("Cargo.toml", &moved.manifest);
    write("Cargo.lock", &moved.lock);
    write("batten.toml", &moved.config);
    next
}

#[test]
fn the_release_rules_are_clean_one_release_ahead() {
    let root = common::at_root(".")
        .canonicalize()
        .expect("this checkout is where the manifest says it is");
    let config =
        batten::config::load(&root.join("batten.toml")).expect("the committed config loads");
    let selected: Vec<rules::Rule> = config
        .rules
        .iter()
        .filter(|rule| {
            rule.kind == RuleKind::Policy
                && rule.scope == RuleScope::Tree
                && rule.module.is_some()
                && rule.base.is_none()
                && rule
                    .sources
                    .iter()
                    .chain(&rule.documents)
                    .chain(&rule.line_sources)
                    .any(|source| MOVED.contains(&source.as_str()))
        })
        .cloned()
        .collect();
    assert!(
        selected.iter().any(|rule| rule.id == "job check other"),
        "the selection carries the row that held v0.0.217: {:?}",
        selected.iter().map(|rule| &rule.id).collect::<Vec<_>>()
    );
    let scratch = common::scratch("release-rehearsal");
    copy_tracked(&root, &scratch);
    let next = move_to_next_release(&scratch);
    let scan = rules::run_static_over(
        &selected,
        &config.provisions,
        batten::policy::Vocabulary::from(&config),
        &scratch,
        rules::RunOptions {
            checks: batten::policy::ModuleChecks::RunOverSelection,
            scope: &rules::Scope::Tree,
            surface: batten::facts::Surface::Check,
            now: None,
        },
    )
    .expect("the selected rows run over the rehearsed tree");
    let found: Vec<String> = scan
        .findings
        .iter()
        .map(|finding| format!("{} {}:{:?}", finding.rule, finding.path, finding.line))
        .collect();
    assert!(
        found.is_empty(),
        "at v{next}, the release PR this tree would cut is refused by a rule it may not \
         satisfy (a release head changes only the release paths): {found:?}"
    );
}
