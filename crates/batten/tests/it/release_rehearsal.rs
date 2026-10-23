//! THE RELEASE REHEARSAL (CLOUD-2515): the tree, one release ahead.
//!
//! The release PR changes two things no feature PR does: release-plz moves the
//! workspace version, and its pin-move step (`release-plz.yml`, "Move the engine
//! pin") moves `batten.toml`'s `engine` line to `v<version>`. A rule whose
//! verdict depends on either is therefore evaluated, for the first time, on the
//! release PR itself, and a head that may touch nothing but the release paths
//! (`release_path::RELEASE_PATHS`) can fix nothing it finds. That is how
//! `ci-parity`'s freeze arm held v0.0.217 red by construction for nine days.
//!
//! This case makes that release PR's state an ordinary PR's question. It copies
//! the tracked tree, applies exactly those two moves at the next patch release,
//! and runs every row that could read them, so a rule only the release PR would
//! trip fails here first, on the change that introduced it.
//!
//! # Which rows
//!
//! A `policy` row on the `tree` scope, with a `module`, no `base`, whose
//! `sources` name `batten.toml` or `Cargo.toml` literally. Each exclusion is a
//! property rather than an id:
//!
//! * a preset row has no `module`, and reads the binary's vendored text;
//! * a `base` row asks git history, which a scratch copy does not carry and the
//!   two moves do not change.
//!
//! # Why `RunOverSelection`
//!
//! The selection is partial, so the registry-exhaustion check a full load makes
//! (every declared verdict raised by some loaded module) would refuse it before
//! any rule ran. `RunOverSelection` is the narrowed caller's entitlement.

use std::fs;
use std::path::Path;

use batten::rules::{self, RuleKind, RuleScope};

use crate::common;

/// The literal sources that carry the two moves.
const MOVED: [&str; 2] = ["batten.toml", "Cargo.toml"];

/// Every tracked file of the checkout at `root`, copied under `scratch`.
fn copy_tracked(root: &Path, scratch: &Path) {
    for path in common::git_in(root, &["ls-files"]).lines() {
        let to = scratch.join(path);
        fs::create_dir_all(to.parent().expect("a tracked file has a parent")).expect("scratch dir");
        // A tracked path deleted in the working tree is not part of the tree a
        // rule reads, so it is not part of the rehearsal either.
        let _ = fs::copy(root.join(path), &to);
    }
}

/// Apply the release PR's two moves to the copy, through the crate's own
/// version step and pin writer, and return the version.
fn move_to_next_release(scratch: &Path) -> String {
    let manifest = fs::read_to_string(scratch.join("Cargo.toml")).expect("Cargo.toml");
    let current = batten::release_path::version_of(&manifest).expect("a workspace version");
    let next = batten::release_state::next_version(&current).expect("a three-part version");
    let moved = manifest.replacen(
        &format!("version = \"{current}\""),
        &format!("version = \"{next}\""),
        1,
    );
    assert_eq!(
        batten::release_path::version_of(&moved).as_deref(),
        Some(next.as_str()),
        "the version moved"
    );
    fs::write(scratch.join("Cargo.toml"), moved).expect("move the version");
    let config = fs::read_to_string(scratch.join("batten.toml")).expect("batten.toml");
    let pin = batten::engine::Pin {
        release: Some(format!("v{next}")),
        source: None,
    };
    fs::write(
        scratch.join("batten.toml"),
        batten::engine::rewrite(&config, &pin),
    )
    .expect("move the pin");
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
