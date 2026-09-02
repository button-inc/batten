//! `batten record closes`, over the compiled binary and the store the reader
//! actually reads.
//!
//! # The seam this tier owns
//!
//! `policy/filed-here.rego`'s `filed-over-own-diff` exempts a row the pull
//! request CLOSES, and reads that from `input.tree.records["pr-closes"]`. Until
//! this verb existed that record had exactly one producer: the `pr-body-closes`
//! `[[recorder]]` row, minted from an observed `gh pr view --jq .body` tool
//! envelope. So the exemption was reachable only when an agent happened to make
//! that call, as a mediated tool call, on a harness whose spelling is surveyed.
//!
//! **Measured on the branch that added this file**: three rows it closes in its
//! own body, all three refused, and no `pr-closes` record in the store at all —
//! while `land` had fetched exactly that body and piped it to
//! `filed-here-check`, whose task body is `batten check`, declared `read`, with
//! no stdin channel. Fetched, handed over, dropped.
//!
//! A module's own `test_` rules cannot see any of that: they fabricate the
//! document, so they pass over a key nothing fills. These cases drive the real
//! writer and then read the file back through the engine's own `record_path`, so
//! a change to the naming reddens here rather than silently pointing the reader
//! and the writer at different files.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};
use std::process::Stdio;

/// A scratch repository on a named branch, with this repository's own
/// `batten.toml` — the authority that declares `ready-issue-key` and
/// `ready-closing-verb`, which the verb resolves its grammar from.
fn repo(name: &str) -> PathBuf {
    let root = common::scratch(name);
    common::git_in(&root, &["init", "--quiet", "--initial-branch", "work"]);
    std::fs::write(root.join("seed.txt"), "seed\n").expect("seed");
    common::git_in(&root, &["add", "-A"]);
    common::git_in(&root, &["commit", "--quiet", "-m", "base"]);
    let authority = common::at_root("batten.toml");
    std::fs::copy(authority, root.join("batten.toml")).expect("install the committed authority");
    root
}

/// Run the verb with `body` on stdin, and return its exit status.
fn record(root: &Path, body: &str) -> std::process::Output {
    let mut child = common::batten()
        .arg("record")
        .arg("closes")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the compiled binary");
    {
        use std::io::Write as _;
        child
            .stdin
            .as_mut()
            .expect("stdin is piped")
            .write_all(body.as_bytes())
            .expect("write the body");
    }
    child.wait_with_output().expect("the verb terminates")
}

/// Read the record back through the engine's own path derivation.
fn recorded(root: &Path) -> Option<String> {
    let git_dir = common::git_in(root, &["rev-parse", "--absolute-git-dir"]);
    let path = batten::recorder::record_path(Path::new(git_dir.trim()), "pr-closes", "work");
    std::fs::read_to_string(path).ok()
}

#[test]
fn a_body_that_closes_rows_records_them_in_the_readers_own_shape() {
    // The positive arm, and the shape is load-bearing rather than cosmetic:
    // `filed-here.rego` splits the column on `:` and the keys on `,`, so a
    // producer that renders them any other way writes a record the reader parses
    // into nothing and the exemption stays dead in a new way.
    let root = repo("record-closes-two");
    let out = record(
        &root,
        "Consolidated.\n\nCloses CLOUD-1295\nCloses CLOUD-1297\n",
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        recorded(&root).as_deref(),
        Some("closes 2:CLOUD-1295,CLOUD-1297\n")
    );
}

#[test]
fn naming_a_row_is_not_closing_it() {
    // CLOUD-674's distinction, which `claimed-keys` learned expensively: a body
    // citing a row as evidence is not moving it. Without this the verb would
    // exempt every row a body mentions, which is strictly worse than the dead
    // exemption it replaces — a gate that reads clean over the punt it exists to
    // price.
    let root = repo("record-closes-cited");
    let out = record(
        &root,
        "This follows the reasoning in CLOUD-761 and refs CLOUD-843.\n",
    );
    assert!(out.status.success(), "{out:?}");
    assert_eq!(recorded(&root).as_deref(), Some("closes 0\n"));
}

#[test]
fn a_body_read_and_closing_nothing_is_a_count_rather_than_an_absence() {
    // THE THREE-VALUED READ, and it is the whole reason the recorder declares
    // `zero-is-a-count`. `closes 0` says the body was READ and closes nothing;
    // no record at all says nobody looked. A producer that skipped the write on
    // an empty key set would collapse them, and the reader has no way back.
    let root = repo("record-closes-zero");
    let out = record(&root, "A body with no keys in it at all.\n");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(recorded(&root).as_deref(), Some("closes 0\n"));
}

#[test]
fn an_empty_body_refuses_rather_than_recording_that_nothing_is_closed() {
    // The direction that must not be silent. An empty stdin is a fetch that
    // failed — `gh pr view` on a branch with no PR prints nothing — and writing
    // `closes 0` for it would convert could-not-look into a measurement, which
    // is the vacuous pass this record's own shape exists to prevent.
    let root = repo("record-closes-empty");
    let out = record(&root, "   \n");
    assert!(!out.status.success());
    assert!(recorded(&root).is_none(), "no record is written");
}

#[test]
fn a_longer_key_is_not_read_as_a_shorter_one_it_contains() {
    // `keys_closed_in` filters `keys_in` rather than searching again, so this is
    // the one definition of a key doing its job here too: `CLOUD-179` must not
    // record `CLOUD-17`. Asserted at this tier because the verb is a new caller
    // of that definition and a new caller is where the boundary gets re-derived.
    let root = repo("record-closes-prefix");
    let out = record(&root, "Closes CLOUD-1790\n");
    assert!(out.status.success(), "{out:?}");
    assert_eq!(recorded(&root).as_deref(), Some("closes 1:CLOUD-1790\n"));
}
