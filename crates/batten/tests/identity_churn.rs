//! Identity across real edits — the identity-churn pack (CLOUD-169).
//!
//! The inline pack in `crates/batten/src/identity.rs` pins the fingerprint
//! construction by handing it span strings written in the test. That is the right
//! shape for "does whitespace collapse survive a reflow", and the wrong shape for
//! "does a rename re-mint": those claims are about what an *edit to a tree* does,
//! so the span has to come out of a file the way the engine takes it.
//!
//! So these drive the real matcher over a real tree. Two reasons this is an
//! integration target rather than more inline tests: the fixture materializer is
//! `tests/common` (CLOUD-63) and `CARGO_TARGET_TMPDIR` is integration-only, and
//! the subject spans two modules — `rules` locates the match, `identity` names
//! it. `tests/primitives.rs` is the precedent for driving the library surface
//! directly: neither module mints a subcommand, so `mise run test` is their gate.
//!
//! **These now run over engine-minted identities** (CLOUD-164). A [`Finding`]
//! carries its own fingerprint, so [`Scan::of`] reads it rather than re-deriving
//! it: the test-side join this pack used to carry is deleted, not kept
//! alongside. That strengthens every fixture below from a claim about the
//! identity *function* to a claim about the extractor too — a span the engine
//! picked wrongly would now fail here, where before there was no extractor to be
//! wrong. The fixtures themselves are unchanged across that switch, which is the
//! evidence that the engine picks the same span the test used to.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use batten::identity::{self, CountChange, Fingerprint};
use batten::rules::{self, Finding, Rule};
use batten::{Config, config};

use common::Fixture;

/// The one ruleset these fixtures scan with: a `forbid` row, which is the only
/// kind that locates a code span today. `glob` and `pattern` are both required
/// for the kind, so both are here.
const FORBID_TODO: &str = "\
version = 1

[[rule]]
id = \"no-todo\"
kind = \"forbid\"
severity = \"deny\"
glob = \"**/*.rs\"
pattern = \"TODO\"
";

/// Rules as a consumer declares them — parsed from TOML rather than built as
/// structs, so a fixture cannot pass against a rule the loader would reject.
fn rules_of(text: &str) -> Vec<Rule> {
    let config: Config = config::parse(text, "identity-churn fixture").unwrap();
    config.rules
}

/// One scan of a tree: what the engine found, and the identity multiset those
/// findings carry.
struct Scan {
    findings: Vec<Finding>,
    identities: BTreeMap<Fingerprint, u64>,
}

impl Scan {
    /// Scan `root` and fold the findings' own identities into a multiset.
    ///
    /// **The engine mints these** (CLOUD-164). The previous version of this
    /// helper read the matched line back out of the file and hashed it here,
    /// because a `Finding` carried no fingerprint — which meant the pack could
    /// pin the identity *function* and never the extractor. The fixtures below
    /// are unchanged across that deletion, and that is the point: they were
    /// written against the whole matched line, and they still pass, so the
    /// engine demonstrably picks the same span the test used to.
    fn of(root: &Path, rules: &[Rule]) -> Self {
        let findings = rules::run_static(rules, root).expect("scan the tree");
        let identities = identity::count_occurrences(
            findings.iter().map(|finding| finding.identity.fingerprint),
        );
        Scan {
            findings,
            identities,
        }
    }

    /// The 1-based line of the only finding, for the fixtures whose whole point
    /// is that identity does *not* follow it.
    fn sole_line(&self) -> usize {
        assert_eq!(
            self.findings.len(),
            1,
            "this fixture seeds exactly one match"
        );
        self.findings[0]
            .line
            .expect("a forbid finding locates a line")
    }

    /// The count this identity is observed at. Absent means **zero in this
    /// context**, which is the reading the resolve rule is written against — not
    /// a missing entry to be skipped.
    fn count(&self, identity: Fingerprint) -> u64 {
        self.identities.get(&identity).copied().unwrap_or(0)
    }

    fn sole_identity(&self) -> (Fingerprint, u64) {
        assert_eq!(
            self.identities.len(),
            1,
            "this fixture seeds exactly one identity"
        );
        let (identity, count) = self.identities.iter().next().expect("just counted one");
        (*identity, *count)
    }
}

#[test]
fn a_rename_re_mints_the_identity_and_resolves_the_old_one() {
    // The path is in the code tuple, so a rename is not a move of one identity —
    // it is a new identity plus a resolve of the old. A store that treated it as
    // a move would carry a disposition across a path the reviewer never saw.
    let root = Fixture::new("identity-churn/rename")
        .file("src/a.rs", "fine\nTODO fix this\n")
        .build();
    let rules = rules_of(FORBID_TODO);

    let before = Scan::of(&root, &rules);
    let (old, anchor) = before.sole_identity();

    fs::rename(root.join("src/a.rs"), root.join("src/b.rs")).unwrap();
    let after = Scan::of(&root, &rules);

    let (new, count) = after.sole_identity();
    assert_ne!(old, new, "a different path is a different identity");
    assert_eq!(
        count, 1,
        "the finding is still one occurrence, at the new path"
    );
    assert_eq!(
        after.count(old),
        0,
        "the old identity is unobserved after the rename"
    );
    assert_eq!(
        identity::compare_to_anchor(anchor, after.count(old)),
        CountChange::Resolved,
        "unobserved at its anchor resolves — never a silent ratchet to zero"
    );
}

#[test]
fn a_file_split_re_partitions_the_multiset() {
    // Two identical spans in one file are ONE identity with a count, so a split
    // is the multiset re-partitioning: the grouped identity resolves and two
    // singletons take its place. Counting per repo instead of per (identity ×
    // context) would make this look like nothing happened.
    let root = Fixture::new("identity-churn/split")
        .file("src/a.rs", "TODO fix this\nmiddle\nTODO fix this\n")
        .build();
    let rules = rules_of(FORBID_TODO);

    let before = Scan::of(&root, &rules);
    let (grouped, anchor) = before.sole_identity();
    assert_eq!(
        anchor, 2,
        "identical spans in one file are one identity + count"
    );

    fs::remove_file(root.join("src/a.rs")).unwrap();
    common::write(&root, "src/one.rs", "TODO fix this\n");
    common::write(&root, "src/two.rs", "TODO fix this\n");
    let after = Scan::of(&root, &rules);

    assert_eq!(after.count(grouped), 0, "the grouped identity is gone");
    assert_eq!(
        identity::compare_to_anchor(anchor, after.count(grouped)),
        CountChange::Resolved
    );
    assert_eq!(after.identities.len(), 2, "one identity per path now");
    assert!(
        after.identities.values().all(|&count| count == 1),
        "each split file carries a single occurrence"
    );
}

#[test]
fn neighbor_edits_preserve_identity() {
    // Inserting and deleting lines around a match moves its line number and
    // nothing else. This is the fixture that pins position out of the tuple: the
    // `file:line` key it replaces would have re-fired every finding below an
    // inserted line.
    let root = Fixture::new("identity-churn/neighbors")
        .file("src/a.rs", "leading\nTODO fix this\ntrailing\n")
        .build();
    let rules = rules_of(FORBID_TODO);

    let before = Scan::of(&root, &rules);
    assert_eq!(before.sole_line(), 2);

    // Two lines added above, the trailing neighbour deleted.
    common::write(&root, "src/a.rs", "added\nadded\nleading\nTODO fix this\n");
    let after = Scan::of(&root, &rules);

    assert_eq!(
        after.sole_line(),
        4,
        "the fixture must really move the match, or it asserts nothing"
    );
    assert_eq!(
        before.identities, after.identities,
        "position is not an input to any fingerprint"
    );
}

#[test]
fn regeneration_churns_only_the_spans_whose_content_changed() {
    // A generated file is rewritten wholesale on every regeneration, so if
    // identity tracked the file rather than the span, every regeneration would
    // re-raise every finding in it — unbounded churn from a no-op.
    const FIRST: &str = "// @generated\nTODO regenerate me\nstable line\n";
    let root = Fixture::new("identity-churn/generated")
        .file("src/gen.rs", FIRST)
        .build();
    let rules = rules_of(FORBID_TODO);

    let first = Scan::of(&root, &rules);
    let (identity, anchor) = first.sole_identity();

    // A byte-identical regeneration is not an edit at all.
    common::write(&root, "src/gen.rs", FIRST);
    let rerun = Scan::of(&root, &rules);
    assert_eq!(
        first.identities, rerun.identities,
        "a byte-identical regeneration keeps every identity"
    );

    // A regeneration that rewrites an *unmatched* line leaves the matched span
    // alone: churn is bounded by the spans whose content changed, never by the
    // size of the diff.
    common::write(
        &root,
        "src/gen.rs",
        "// @generated\nTODO regenerate me\nrewritten line\n",
    );
    let changed = Scan::of(&root, &rules);
    assert_eq!(
        changed.count(identity),
        anchor,
        "an unmatched line moving does not touch the matched span's identity"
    );
    assert_eq!(
        identity::compare_to_anchor(anchor, changed.count(identity)),
        CountChange::Unchanged,
        "so there is nothing to report"
    );
}
