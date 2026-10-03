//! The trunk's tracking ref after a landing (CLOUD-2085).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

#[test]
fn a_landed_branch_leaves_the_tracking_ref_at_the_landed_head() {
    // The shared template rather than a hand-rolled `git init`
    // (`policy/fixture-forks.rego`).
    let root = common::Fixture::new("land-tracking")
        .file("a.txt", "one\n")
        .git()
        .base_commit()
        .build();
    common::git_in(&root, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    common::git_in(&root, &["checkout", "-qb", "feature"]);
    common::write(&root, "a.txt", "two\n");
    common::git_in(&root, &["commit", "-qam", "the landed change"]);

    let recorded = batten::land::record_landed_trunk(&root, "main", "feature").unwrap();
    assert!(recorded, "the branch resolves, so its tip is recorded");

    let tip = batten::git::resolve_ref(&root, "refs/heads/feature").unwrap();
    let tracking = batten::git::resolve_ref(&root, "refs/remotes/origin/main").unwrap();
    assert_eq!(
        tracking, tip,
        "an accepted fast-forward made the trunk this tip, so the tracking ref says so"
    );
}
