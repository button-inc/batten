//! A dev pre-release's tag is never read as a release (CLOUD-2903).
//!
//! `engine::forge_tag` publishes a dev pre-release under `dev/`, outside `v*`,
//! because every reader of this repository's releases selects `v*`. Each case
//! feeds the tag `forge_tag` mints for a dev pin to one of those readers, beside
//! a real release tag, and shows the reader still answers with the release.
//! The anti-vacuity half of the first case shows the namespace is what
//! protects it: the same version under `v*` IS read as the newest release.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

const RELEASE: &str = "v0.0.221";
const DEV_PIN: &str = "v0.0.222-dev.pr1290.20261124120000+abcdef012345";

fn dev_tag() -> String {
    batten::engine::forge_tag(DEV_PIN)
}

/// A repository with one commit carrying [`RELEASE`] and every tag in `more`.
fn tagged(name: &str, more: &[&str]) -> PathBuf {
    let dir = common::scratch(name);
    common::write(&dir, "README.md", "x\n");
    common::init_repo(&dir);
    common::git_in(&dir, &["add", "README.md"]);
    common::git_in(&dir, &["commit", "-q", "-m", "one"]);
    common::git_in(&dir, &["tag", RELEASE]);
    for tag in more {
        common::git_in(&dir, &["tag", tag]);
    }
    dir
}

#[test]
fn the_dev_tag_is_namespaced() {
    assert!(dev_tag().starts_with(batten::engine::DEV_TAG_PREFIX));
    assert!(!dev_tag().starts_with('v'));
}

/// `git::newest_version_tag`, the release baseline `release plan` and the
/// changelog read.
#[test]
fn a_dev_tag_is_never_the_newest_release_tag() {
    let dir = tagged("dev-tags-newest", &[&dev_tag()]);
    assert_eq!(
        batten::git::newest_version_tag(&dir).unwrap().as_deref(),
        Some(RELEASE)
    );
    // ANTI-VACUITY: the same version under `v*` would be read as the release.
    let unspaced = dev_tag()
        .trim_start_matches(batten::engine::DEV_TAG_PREFIX)
        .to_owned();
    let exposed = tagged("dev-tags-newest-exposed", &[&unspaced]);
    assert_eq!(
        batten::git::newest_version_tag(&exposed).unwrap(),
        Some(unspaced)
    );
}

/// The glob this repository's `release-tags` history row declares, which is
/// every tag `tag mint wrong` (`policy/release-tag-shape.rego`) judges.
fn release_tags_glob() -> String {
    let text =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../batten.toml"))
            .unwrap();
    let config: toml::Table = toml::from_str(&text).unwrap();
    config["rule"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|rule| rule.get("history")?.as_array())
        .flatten()
        .find(|row| row.get("id").and_then(toml::Value::as_str) == Some("release-tags"))
        .and_then(|row| row.get("tags")?.as_str())
        .expect("batten.toml declares the release-tags history row")
        .to_owned()
}

/// The `release-tags` glob, as `git::tag_facts` resolves it for `tag mint
/// wrong`: the dev tag is never among the tags that rule judges.
#[test]
fn a_dev_tag_is_never_among_the_release_tags_the_mint_rule_judges() {
    let glob = release_tags_glob();
    let dir = tagged("dev-tags-glob", &[&dev_tag()]);
    let facts = batten::git::tag_facts(&dir, std::slice::from_ref(&glob)).unwrap();
    let tags: Vec<&str> = facts[&glob].iter().map(|fact| fact.tag.as_str()).collect();
    assert_eq!(tags, [RELEASE]);
}

/// The release guard's tag ruleset (`release_guard.rs`), which protects
/// `refs/tags/v*`: a dev tag is never under it, so publishing one never needs
/// the release path's bypass.
#[test]
fn a_dev_tag_is_never_under_the_release_tag_ruleset() {
    assert!(batten::git::tag_glob_matches(
        "refs/tags/v*",
        &format!("refs/tags/{RELEASE}")
    ));
    assert!(!batten::git::tag_glob_matches(
        "refs/tags/v*",
        &format!("refs/tags/{}", dev_tag())
    ));
}

/// release-plz's `git_only` baseline reads the tag its `git_tag_name`
/// template spells, `v{{ version }}` unless `release-plz.toml` says otherwise;
/// the dev tag never has that shape.
#[test]
fn a_dev_tag_is_never_release_plzs_baseline() {
    let text = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../release-plz.toml"),
    )
    .unwrap();
    let config: toml::Table = toml::from_str(&text).unwrap();
    let template = config
        .get("workspace")
        .and_then(|workspace| workspace.get("git_tag_name"))
        .and_then(toml::Value::as_str)
        .unwrap_or("v{{ version }}");
    let prefix = template.split("{{").next().unwrap();
    assert_eq!(prefix, "v", "the baseline template is `v{{{{ version }}}}`");
    assert!(!dev_tag().starts_with(prefix));
}
