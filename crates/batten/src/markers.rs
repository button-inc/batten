//! Counted suppression markers (CLOUD-36): how many times has policy been
//! waved through, and where?
//!
//! A suppression marker is an in-source comment that switches a rule off for
//! one place — the "this line is exempt" shape every linter eventually grows,
//! spelled differently by each one.
//! Batten's interest in them is not the switching, which belongs to whatever
//! rule they suppress; it is the **count**. A suppression is a policy decision
//! recorded in the tree, and a count that only ever rises is the observable
//! form of a gate quietly being abandoned. So the primitive that lands here
//! answers "how many, and where", and leaves the ratchet to the advisory
//! subsystem that owns dispositions.
//!
//! Load-bearing choices:
//!
//! * **The tokens are config, never crate constants** (non-negotiable rule 1).
//!   A marker's spelling is a property of the repository being gated, not of
//!   Batten, so `crates/batten` contains no marker literal and a grep for one
//!   returns zero hits. Batten's own markers live in Batten's own
//!   `batten.toml`, as consumer #1.
//! * **Output is a pointer, never the payload** (rule 4): a [`Hit`] carries the
//!   marker id and `path:line`, never the line's bytes. A suppression comment
//!   is exactly the kind of text that quotes the thing being suppressed.
//! * **Identical markers in one file are one identity with a count**, matching
//!   [`crate::identity::count_occurrences`]: [`counts`] is a multiset, so a
//!   file that suppresses the same rule twice reads as two occurrences of one
//!   marker rather than two unrelated findings.
//! * **The tree walk is [`crate::rules::tree_files`]**, not a second walker.
//!   Two answers to "what does Batten look at" is the divergence this module
//!   would otherwise introduce.
//!
//! Scanning is inspection-only and byte-stable: for identical config and
//! identical tree bytes it returns the identical, sorted hit list.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules;

/// One suppression marker declared in `batten.toml`.
///
/// The two fields are deliberately separate axes: `id` is the stable name a
/// count is reported under and may not change when the spelling does, while
/// `token` is the literal text scanned for. Collapsing them would make every
/// re-spelling of a marker look like a brand-new one whose count starts at
/// zero — the ratchet defeated by a rename.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    /// The stable identifier counts are reported under.
    pub id: String,
    /// The literal text that marks a suppression. Matched as a substring, not a
    /// pattern: a marker is a fixed shape an author types, and admitting a
    /// regex here would make the count a function of an expression rather than
    /// of the tree.
    pub token: String,
    /// Which files this marker is looked for in, as a `/`-separated glob. Omit
    /// to scan the whole tree.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub glob: Option<String>,
}

impl Marker {
    /// Reject a marker that cannot honestly be counted.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an empty
    /// `token` — which would match every line of every file — or an empty
    /// `glob`, which reads as "everywhere" but selects nothing.
    fn validate(&self) -> Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("marker: `id` must not be empty"));
        }
        if self.token.is_empty() {
            return Err(UsageError::raise(format!(
                "marker {}: `token` must not be empty; an empty token matches every line",
                self.id
            )));
        }
        if self.glob.as_deref() == Some("") {
            return Err(UsageError::raise(format!(
                "marker {}: `glob` must not be empty; omit the key to scan the whole tree",
                self.id
            )));
        }
        Ok(())
    }

    /// Whether this marker looks at `path`.
    fn selects(&self, path: &str) -> bool {
        self.glob
            .as_ref()
            .is_none_or(|glob| rules::glob_match(glob, path))
    }
}

/// One occurrence of a marker: the pointer, never the line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[non_exhaustive]
pub struct Hit {
    /// The repo-relative, `/`-separated path.
    pub path: String,
    /// The 1-based line the marker appears on.
    pub line: usize,
    /// The [`Marker::id`] that matched.
    pub marker: String,
}

/// Find every occurrence of every marker under `root`.
///
/// Hits come back sorted by `(path, line, marker)` — the same pointer tuple
/// [`crate::rules`] sorts findings by — so identical input yields identical
/// output whatever order the filesystem enumerated in.
///
/// A file whose bytes are not UTF-8 is skipped rather than refused: a
/// repository legitimately contains binaries, and a marker is by definition
/// text an author typed. A file that cannot be *read* is a different matter and
/// propagates, because silently counting zero markers in a file nobody could
/// open is the false-clean answer this module must not give.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed marker, and an
/// internal error (→ exit `3`) when the tree cannot be walked or a file cannot
/// be read.
pub fn find(root: &Path, markers: &[Marker]) -> Result<Vec<Hit>> {
    for marker in markers {
        marker.validate()?;
    }
    // Cheap when irrelevant (house-style §4): no markers configured means no
    // tree walk at all.
    if markers.is_empty() {
        return Ok(Vec::new());
    }
    let mut hits = Vec::new();
    for path in rules::tree_files(root)? {
        let selecting: Vec<&Marker> = markers
            .iter()
            .filter(|marker| marker.selects(&path))
            .collect();
        if selecting.is_empty() {
            continue;
        }
        let Ok(text) = fs::read_to_string(root.join(&path)) else {
            // Not UTF-8, or not readable as text: no marker can be in it.
            continue;
        };
        for (index, line) in text.lines().enumerate() {
            for marker in &selecting {
                if line.contains(&marker.token) {
                    hits.push(Hit {
                        path: path.clone(),
                        line: index + 1,
                        marker: marker.id.clone(),
                    });
                }
            }
        }
    }
    hits.sort();
    Ok(hits)
}

/// Fold hits into the multiset a budget or ratchet reads: one entry per marker
/// id, valued by how many times it occurs.
///
/// Every configured marker appears, including at zero — an absent key and a
/// zero count are different claims, and a consumer comparing against a recorded
/// anchor must be able to tell "none now" from "not measured".
#[must_use]
pub fn counts(markers: &[Marker], hits: &[Hit]) -> BTreeMap<String, u64> {
    let mut counts: BTreeMap<String, u64> = markers
        .iter()
        .map(|marker| (marker.id.clone(), 0))
        .collect();
    for hit in hits {
        *counts.entry(hit.marker.clone()).or_insert(0) += 1;
    }
    counts
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn marker(id: &str, token: &str) -> Marker {
        Marker {
            id: id.to_owned(),
            token: token.to_owned(),
            glob: None,
        }
    }

    #[test]
    fn a_marker_that_cannot_be_counted_is_a_usage_error() {
        for broken in [
            marker("", "x"),
            marker("m", ""),
            Marker {
                id: "m".to_owned(),
                token: "x".to_owned(),
                glob: Some(String::new()),
            },
        ] {
            let err = broken.validate().unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "a malformed marker is bad config, not an internal failure"
            );
        }
    }

    #[test]
    fn counts_report_every_configured_marker_including_zero() {
        // An absent key and a zero count are different claims: "none now" must
        // be distinguishable from "not measured".
        let markers = [marker("seen", "A"), marker("unseen", "B")];
        let hits = vec![Hit {
            path: "a.rs".to_owned(),
            line: 1,
            marker: "seen".to_owned(),
        }];
        let counts = counts(&markers, &hits);
        assert_eq!(counts.get("seen"), Some(&1));
        assert_eq!(counts.get("unseen"), Some(&0));
    }

    #[test]
    fn repeated_occurrences_are_one_identity_with_a_count() {
        let markers = [marker("m", "A")];
        let hits = vec![
            Hit {
                path: "a.rs".to_owned(),
                line: 1,
                marker: "m".to_owned(),
            },
            Hit {
                path: "a.rs".to_owned(),
                line: 7,
                marker: "m".to_owned(),
            },
        ];
        assert_eq!(counts(&markers, &hits).get("m"), Some(&2));
    }

    #[test]
    fn the_source_bakes_in_no_marker_token() {
        // Non-negotiable rule 1, as a grep over this module's own source: the
        // tokens are config, so the only marker text here is a test fixture's.
        // Anything that looks like a real-world suppression spelling would mean
        // a consumer's vocabulary had leaked into the core.
        let source = include_str!("markers.rs");
        for baked in [
            ["no", "qa"].concat(),
            ["no", "lint"].concat(),
            ["batten", ":allow"].concat(),
            ["batten", "-ignore"].concat(),
        ] {
            assert!(
                !source.contains(&baked),
                "markers source hardcodes {baked:?}; marker tokens come from batten.toml"
            );
        }
    }
}
