//! The trunk's tracking ref after a landing (CLOUD-2085).

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

#[test]
fn a_landed_branch_leaves_the_tracking_ref_at_the_landed_head() {
    let root = common::scratch("land-tracking");
    common::git_in(&root, &["init", "-q", "-b", "main"]);
    // gix writes a reflog entry with the ref, and refuses one with no committer.
    common::git_in(&root, &["config", "user.name", "fixture"]);
    common::git_in(&root, &["config", "user.email", "fixture@example.invalid"]);
    common::write(&root, "a.txt", "one\n");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "-qm", "seed"]);
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
