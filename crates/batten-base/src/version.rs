//! The one reading of a version string: Semantic Versioning 2.0.0, through the
//! `semver` crate (CLOUD-2906).
//!
//! Every version batten decides over — a release tag, an engine pin,
//! `min_batten_version`, the dev pre-release identity (CLOUD-2903), a preset's
//! version — is semver, and every reader parses it here rather than splitting,
//! stripping or comparing the text by hand. Three rules, one per section of the
//! spec a hand-rolled reader got wrong:
//!
//! - **§11: a pre-release orders BELOW its release.** [`precedence`] is
//!   `Version::cmp_precedence`; digit runs compared by hand rank `1.0.0-rc.1`
//!   above `1.0.0`.
//! - **§10: build metadata never orders.** `semver::Version`'s derived `Ord`
//!   ranks `1.0.0+b` above `1.0.0+a`, so it is never used to order; identity
//!   ("is this the pinned release") is full equality, metadata included.
//! - **A pre-release is never shipped.** [`Tag::is_release`] is the one
//!   "shipped" predicate.
//!
//! A release tag is exactly one leading `v` then a version ([`Tag::parse`]):
//! `vv1.0.0`, a bare `1.0.0`, `v01.0.0` and `v1.0` are not tags.
//!
//! # Effect
//!
//! None: pure functions over strings.

use std::cmp::Ordering;
use std::fmt;

pub use semver::Version;

/// The one character batten's own release tag carries before its version.
pub const TAG_PREFIX: char = 'v';

/// A release tag: [`TAG_PREFIX`] once, then a semver 2.0.0 version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    /// The version the tag names, build metadata included.
    pub version: Version,
}

impl Tag {
    /// The tag `text` names, or `None` when it is not exactly one `v` and a
    /// semver version.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let bare = text.strip_prefix(TAG_PREFIX)?;
        parse(bare).map(|version| Self { version })
    }

    /// The tag for `version`.
    #[must_use]
    pub const fn of(version: Version) -> Self {
        Self { version }
    }

    /// Whether this tag is a release: no pre-release identifier (§9).
    #[must_use]
    pub fn is_release(&self) -> bool {
        is_release(&self.version)
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{TAG_PREFIX}{}", self.version)
    }
}

/// The semver version `text` spells, with no prefix, or `None`.
#[must_use]
pub fn parse(text: &str) -> Option<Version> {
    Version::parse(text).ok()
}

/// The version `text` spells, written with or without ONE leading `v`.
///
/// For a reader whose grammar admits both spellings (a provision row's
/// `version`); a tag reader uses [`Tag::parse`], which requires the `v`.
#[must_use]
pub fn parse_lenient(text: &str) -> Option<Version> {
    text.strip_prefix(TAG_PREFIX)
        .map_or_else(|| parse(text), parse)
}

/// Whether `version` is a release: its pre-release is empty.
#[must_use]
pub fn is_release(version: &Version) -> bool {
    version.pre.is_empty()
}

/// Semver §11 precedence: a pre-release below its release, build metadata
/// ignored. The only ordering any reader uses.
#[must_use]
pub fn precedence(a: &Version, b: &Version) -> Ordering {
    a.cmp_precedence(b)
}

/// The version a tag under a consumer's declared glob names: the glob's literal
/// prefix (the text before its first wildcard) stripped ONCE, then parsed.
/// `v[0-9]*` strips `v`; a glob with no literal prefix strips nothing.
///
/// The prefix comes from the consumer's own config, so no `v` enters the core
/// for a consumer's tags (non-negotiable rule 1).
#[must_use]
pub fn under_glob(tag: &str, glob: &str) -> Option<Version> {
    parse(tag.strip_prefix(glob_prefix(glob))?)
}

/// The literal text before the first glob metacharacter of `glob`.
#[must_use]
pub fn glob_prefix(glob: &str) -> &str {
    let end = glob.find(['*', '?', '[']).unwrap_or(glob.len());
    &glob[..end]
}

/// Whether `tag` is a RELEASE under `glob`: it parses under the glob's prefix
/// and carries no pre-release.
#[must_use]
pub fn is_release_under(tag: &str, glob: &str) -> bool {
    under_glob(tag, glob).is_some_and(|version| is_release(&version))
}

/// The pre-semver integer header `N` read as `0.0.N` (an earlier ruling): the
/// one place an integer stands for a version.
#[must_use]
pub const fn from_integer(n: u64) -> Version {
    Version::new(0, 0, n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEV: &str = "v0.0.221-dev.pr1282.20261124T050057Z+3f9c2a1b7d04";

    fn tag(text: &str) -> Tag {
        Tag::parse(text).unwrap_or_else(|| panic!("{text} is a tag"))
    }

    #[test]
    fn a_pre_release_orders_below_its_release_and_is_never_a_release() {
        let dev = tag(DEV);
        assert!(!dev.is_release());
        assert_eq!(
            precedence(&dev.version, &tag("v0.0.220").version),
            Ordering::Greater
        );
        assert_eq!(
            precedence(&dev.version, &tag("v0.0.221").version),
            Ordering::Less
        );
        assert!(tag("v0.0.221").is_release());
        assert_eq!(dev.to_string(), DEV);
    }

    #[test]
    fn build_metadata_never_changes_precedence() {
        let a = tag("v1.0.0+a").version;
        let b = tag("v1.0.0+b").version;
        let bare = tag("v1.0.0").version;
        assert_eq!(precedence(&a, &b), Ordering::Equal);
        assert_eq!(precedence(&bare, &a), Ordering::Equal);
        assert_ne!(a, b);
        assert_ne!(bare, a);
    }

    #[test]
    fn a_tag_is_exactly_one_v_then_semver() {
        for refused in [
            "vv1.0.0",
            "1.0.0",
            "v01.0.0",
            "v1.0",
            "vnext",
            "v0.0.221-dev.pr1282.2026-11-24T05:00:57Z+3f9c2a1b7d04",
        ] {
            assert_eq!(Tag::parse(refused), None, "{refused}");
        }
        assert_eq!(tag("v1.2.3").version, Version::new(1, 2, 3));
    }

    #[test]
    fn a_glob_prefix_is_stripped_once_and_a_pre_release_is_not_a_release_under_it() {
        assert_eq!(glob_prefix("v[0-9]*"), "v");
        assert_eq!(glob_prefix("*"), "");
        assert_eq!(glob_prefix("release-*"), "release-");
        assert!(is_release_under("v1.1.0", "v[0-9]*"));
        assert!(!is_release_under("v1.1.0-rc.1", "v[0-9]*"));
        assert!(!is_release_under("vv1.1.0", "v[0-9]*"));
        assert!(!is_release_under("v0.99", "v[0-9]*"));
        assert!(is_release_under("1.0.0", "*"));
        assert_eq!(
            under_glob("release-2.0.0+x", "release-*").map(|v| v.to_string()),
            Some("2.0.0+x".to_owned())
        );
    }

    #[test]
    fn a_lenient_pin_takes_one_optional_v() {
        assert_eq!(parse_lenient("v1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(parse_lenient("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(parse_lenient("vv1.2.3"), None);
    }

    #[test]
    fn the_old_integer_header_reads_as_zero_zero_n() {
        assert_eq!(from_integer(7).to_string(), "0.0.7");
    }
}
