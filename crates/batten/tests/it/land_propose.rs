//! `land replay --propose` over a real conflicting repository (CLOUD-1956).
//!
//! `propose.rs`'s unit cases pin the shapes over bytes. This tier pins what they
//! cannot: that the REPLAY hands the right three sides to them — trunk as ours,
//! the commit's parent as the ancestor, the commit as theirs — that a candidate
//! lands under the directory it was given, and that proposing moves nothing. A
//! candidate built from the wrong side would pass every unit case.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use batten::gitwrite::{self, Rebase};
use batten::propose::Shape;

type Files<'a> = &'a [(&'a str, &'a str)];

fn init(name: &str) -> (PathBuf, gix::Repository) {
    let dir = common::scratch(name);
    let repo = gix::init(&dir).expect("init");
    let mut config = std::fs::read_to_string(dir.join(".git/config")).expect("read config");
    config.push_str("[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n");
    std::fs::write(dir.join(".git/config"), config).expect("write config");
    let repo = gix::open(repo.path()).expect("reopen");
    (dir, repo)
}

fn commit(repo: &gix::Repository, parents: &[gix::ObjectId], files: Files<'_>) -> gix::ObjectId {
    let who = gix::actor::Signature {
        name: "Fixture".into(),
        email: "fixture@example.invalid".into(),
        time: gix::date::Time::new(1_700_000_000, 0),
    };
    let mut entries: Vec<gix::objs::tree::Entry> = files
        .iter()
        .map(|(name, body)| gix::objs::tree::Entry {
            mode: gix::objs::tree::EntryKind::Blob.into(),
            filename: (*name).into(),
            oid: repo.write_blob(body.as_bytes()).expect("blob").detach(),
        })
        .collect();
    entries.sort_by(|left, right| left.filename.cmp(&right.filename));
    let tree = repo
        .write_object(&gix::objs::Tree { entries })
        .expect("tree")
        .detach();
    repo.write_object(&gix::objs::Commit {
        tree,
        parents: parents.iter().copied().collect(),
        author: who.clone(),
        committer: who,
        encoding: None,
        message: "fixture\n".into(),
        extra_headers: Vec::new(),
    })
    .expect("commit")
    .detach()
}

fn point(dir: &Path, reference: &str, id: gix::ObjectId) {
    gitwrite::set_ref(dir, reference, &id.to_hex().to_string()).expect("set ref");
}

/// A trunk and a branch that each changed `config.toml` from `base`, with the
/// branch checked out. Returns the repo dir and the branch tip.
fn raced(name: &str, base: &str, trunk: &str, branch: &str) -> (PathBuf, gix::ObjectId) {
    let (dir, repo) = init(name);
    let root = commit(&repo, &[], &[("config.toml", base)]);
    let moved = commit(&repo, &[root], &[("config.toml", trunk)]);
    let tip = commit(&repo, &[root], &[("config.toml", branch)]);
    point(&dir, "refs/heads/main", moved);
    point(&dir, "refs/heads/work", tip);
    std::fs::write(dir.join("config.toml"), branch).expect("materialise the branch");
    (dir, tip)
}

fn head_of(dir: &Path) -> String {
    let repo = gix::open(dir).expect("open");
    repo.find_reference("refs/heads/work")
        .expect("the branch ref")
        .id()
        .to_hex()
        .to_string()
}

/// THE #928 SHAPE: both sides grew one comma list. The candidate keeps trunk's
/// order and appends the branch's item, and the replay still stops and moves
/// nothing — a proposal is read, never applied.
#[test]
fn a_list_both_sides_grew_is_proposed_in_trunk_order_and_nothing_moves() {
    let (dir, tip) = raced(
        "propose-list-race",
        "GATES = \"b,a\"\n",
        "GATES = \"b,a,trunk\"\n",
        "GATES = \"b,a,branch\"\n",
    );
    let into = dir.join(".git/batten-propose");

    let (outcome, candidates) =
        gitwrite::rebase_proposing(&dir, "refs/heads/work", "refs/heads/main", &[], &into)
            .expect("the replay runs");

    assert!(
        matches!(outcome, Rebase::Conflicted { ref paths, .. } if paths == &["config.toml".to_owned()]),
        "a proposal is not a resolution: the replay still stops, got {outcome:?}"
    );
    assert_eq!(head_of(&dir), tip.to_hex().to_string(), "no ref moved");
    let [candidate] = candidates.as_slice() else {
        panic!("one candidate per conflicted path, got {candidates:?}");
    };
    let (file, shapes) = candidate.proposal.as_ref().expect("a list-union candidate");
    assert_eq!(shapes, &vec![Shape::ListUnion]);
    assert_eq!(
        std::fs::read_to_string(file).expect("the candidate is written"),
        "GATES = \"b,a,trunk,branch\"\n",
        "trunk's order, the branch's item appended — never sorted"
    );
    assert!(file.starts_with(&into), "written under the directory given");
}

/// `#MUTANT undeclared-hunk-proposed` reddens here. A code line both sides
/// changed matches no shape, so the path gets NO candidate — never a guess.
#[test]
fn an_unshaped_region_gets_no_candidate() {
    let (dir, _) = raced(
        "propose-unshaped",
        "timeout = 10\n",
        "timeout = 20\n",
        "timeout = 30\n",
    );
    let into = dir.join(".git/batten-propose");

    let (_, candidates) =
        gitwrite::rebase_proposing(&dir, "refs/heads/work", "refs/heads/main", &[], &into)
            .expect("the replay runs");

    let [candidate] = candidates.as_slice() else {
        panic!("the conflicted path is still reported, got {candidates:?}");
    };
    assert_eq!(candidate.proposal, None, "no shape, no candidate");
    assert!(
        !into.join("config.toml").exists(),
        "nothing is written for it"
    );
}

/// The unattended path is untouched: without `into`, nothing is proposed or
/// written, and the conflict is exactly what it always was.
#[test]
fn a_replay_that_does_not_ask_proposes_nothing() {
    let (dir, _) = raced(
        "propose-not-asked",
        "GATES = \"a\"\n",
        "GATES = \"a,trunk\"\n",
        "GATES = \"a,branch\"\n",
    );
    let outcome = gitwrite::rebase_resolving(&dir, "refs/heads/work", "refs/heads/main", &[])
        .expect("the replay runs");
    assert!(matches!(outcome, Rebase::Conflicted { .. }));
    assert!(
        !dir.join(".git/batten-propose").exists(),
        "a replay that did not ask writes no proposal"
    );
}
