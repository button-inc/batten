//! Replaying a branch onto a moved base, over the real engine (CLOUD-1274's
//! successor campaign, stage D3).
//!
//! # The case that has to exist, and why the clean one alone proves nothing
//!
//! `mem:workflow/landing-loop` gives the landing loop exactly one human stop:
//! *"the only stop is a rebase that conflicts."* `gix-merge` will happily resolve
//! a conflict with a strategy and report success, so a suite that exercises only
//! the clean replay passes **over an auto-resolving implementation** — which is
//! the one behaviour the design forbids. [`a_conflicting_replay_refuses`] is
//! therefore the load-bearing case here and the clean one is its control.
//!
//! **What that case does NOT discriminate, said plainly rather than left to be
//! assumed:** it separates *refusing* from *resolving*, and it does not separate
//! `TreatAsUnresolved::forced_resolution` from the laxer `git()` — a two-sided
//! edit of one line is unresolved under either. Catching a downgrade between
//! those two needs a fixture where a resolution STRATEGY is what settles it, and
//! the landed options configure no strategy, so there is nothing here to build
//! one from yet. The strict reading is still what the code asks for; this suite
//! is simply not the sensor on that half.
//!
//! # No `git` binary anywhere in this file
//!
//! The fixtures are built with `gix` and with `gitwrite`'s own writes, so what
//! these cases drive is the engine rather than a shell-out that happens to agree
//! with it. That is not tidiness: `git.rs`'s `no_second_git_invoker_exists` is
//! the property this whole campaign exists to keep, and a suite that reaches for
//! `git` to build its own fixtures is asserting nothing about a `git`-free
//! engine.

#![cfg(unix)]

use crate::common;

use std::path::{Path, PathBuf};

use batten::gitwrite::{self, Rebase};

use common::scratch;

/// A commit's ingredients: the files its tree carries, flat.
type Files<'a> = &'a [(&'a str, &'a str)];

/// Initialise a repository with a worktree and a configured committer.
fn init(name: &str) -> (PathBuf, gix::Repository) {
    let dir = scratch(name);
    let repo = gix::init(&dir).expect("init");
    // A commit needs an identity, and the ambient one is not this test's to
    // depend on — a container with no `user.email` would otherwise fail here for
    // a reason that has nothing to do with the replay.
    let mut config = std::fs::read_to_string(dir.join(".git/config")).expect("read config");
    config.push_str("[user]\n\tname = Fixture\n\temail = fixture@example.invalid\n");
    std::fs::write(dir.join(".git/config"), config).expect("write config");
    let repo = gix::open(repo.path()).expect("reopen");
    (dir, repo)
}

/// Write a flat tree and a commit on top of `parents`, returning the commit id.
fn commit(repo: &gix::Repository, parents: &[gix::ObjectId], files: Files<'_>) -> gix::ObjectId {
    let mut entries: Vec<gix::objs::tree::Entry> = files
        .iter()
        .map(|(name, body)| gix::objs::tree::Entry {
            mode: gix::objs::tree::EntryKind::Blob.into(),
            filename: (*name).into(),
            oid: repo.write_blob(body.as_bytes()).expect("blob").detach(),
        })
        .collect();
    // Git's tree format REQUIRES sorted entries, and an unsorted one still hashes
    // and still writes — so the fixture would be subtly invalid rather than
    // rejected.
    entries.sort_by(|left, right| left.filename.cmp(&right.filename));
    let tree = repo
        .write_object(&gix::objs::Tree { entries })
        .expect("tree")
        .detach();
    let who = gix::actor::Signature {
        name: "Fixture".into(),
        email: "fixture@example.invalid".into(),
        // A FIXED instant, so two fixture commits built in the same second are
        // still distinguishable only by their content — which is what makes an
        // assertion about a minted sha an assertion about the replay.
        time: gix::date::Time::new(1_700_000_000, 0),
    };
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

/// Put `files` on disk, so the fixture looks like a checked-out clone.
fn materialise(dir: &Path, files: Files<'_>) {
    for (name, body) in files {
        std::fs::write(dir.join(name), body).expect("write worktree file");
    }
}

fn point(dir: &Path, reference: &str, id: gix::ObjectId) {
    gitwrite::set_ref(dir, reference, &id.to_hex().to_string()).expect("set ref");
}

/// A branch replayed onto a base that moved underneath it lands every commit,
/// and the result carries BOTH sides' files.
#[test]
fn a_clean_replay_lands_every_commit() {
    let (dir, repo) = init("rebase-clean");
    let root: Files<'_> = &[("shared.txt", "base\n")];
    let base = commit(&repo, &[], root);

    let trunk: Files<'_> = &[("shared.txt", "base\n"), ("from-main.txt", "trunk\n")];
    let moved = commit(&repo, &[base], trunk);

    let side: Files<'_> = &[("shared.txt", "base\n"), ("from-branch.txt", "work\n")];
    let tip = commit(&repo, &[base], side);

    point(&dir, "refs/heads/main", moved);
    point(&dir, "refs/heads/work", tip);
    materialise(&dir, side);

    let outcome = gitwrite::rebase(&dir, "refs/heads/work", "refs/heads/main").expect("rebase");
    let Rebase::Replayed { head, commits } = outcome else {
        panic!("expected a clean replay, got {outcome:?}");
    };
    assert_eq!(commits, 1, "one commit was in the range");
    assert_ne!(
        head,
        tip.to_hex().to_string(),
        "a replay mints a new sha, or it did not replay"
    );

    // The REF moved, not just the return value: a function that reports a head it
    // did not write is the failure this asserts against.
    let landed = repo
        .rev_parse_single("refs/heads/work")
        .expect("resolve work")
        .detach();
    assert_eq!(landed.to_hex().to_string(), head);

    // The new commit descends from the moved base and carries both sides.
    let replayed = repo.find_commit(landed).expect("find replayed");
    assert_eq!(
        replayed
            .parent_ids()
            .map(gix::Id::detach)
            .collect::<Vec<_>>(),
        vec![moved],
        "the replayed commit sits on the moved base"
    );
    let names = tree_names(&repo, landed);
    assert!(
        names.contains(&"from-main.txt".to_owned())
            && names.contains(&"from-branch.txt".to_owned()),
        "the merged tree carries both sides, got {names:?}"
    );

    // And the WORKTREE carries the path the base introduced, which is the half a
    // tree-only assertion never reaches.
    assert!(
        dir.join("from-main.txt").is_file(),
        "the worktree was not updated"
    );
}

/// **The case the design exists for.** Two sides edit one path, and the replay
/// REFUSES rather than resolving. Nothing moves.
#[test]
fn a_conflicting_replay_refuses() {
    let (dir, repo) = init("rebase-conflict");
    let root: Files<'_> = &[("shared.txt", "base\n")];
    let base = commit(&repo, &[], root);

    let trunk: Files<'_> = &[("shared.txt", "the trunk's line\n")];
    let moved = commit(&repo, &[base], trunk);

    let side: Files<'_> = &[("shared.txt", "the branch's line\n")];
    let tip = commit(&repo, &[base], side);

    point(&dir, "refs/heads/main", moved);
    point(&dir, "refs/heads/work", tip);
    materialise(&dir, side);

    let outcome = gitwrite::rebase(&dir, "refs/heads/work", "refs/heads/main").expect("rebase");
    let Rebase::Conflicted { commit, paths } = outcome else {
        panic!("a conflicting replay must refuse, got {outcome:?}");
    };
    assert_eq!(
        commit,
        tip.to_hex().to_string(),
        "the refusal names the ORIGINAL commit that would not replay"
    );
    assert_eq!(
        paths,
        vec!["shared.txt".to_owned()],
        "the refusal points at the path, and carries no content"
    );

    // NOTHING MOVED. A refusal that left a half-rebased branch would be worse
    // than one that resolved, because the next lap would start from it.
    let still = repo
        .rev_parse_single("refs/heads/work")
        .expect("resolve work")
        .detach();
    assert_eq!(still, tip, "the branch is untouched after a refusal");
    assert_eq!(
        std::fs::read_to_string(dir.join("shared.txt")).expect("read worktree"),
        "the branch's line\n",
        "the worktree is untouched after a refusal, and carries no conflict markers"
    );
}

/// A branch that already descends from the base mints nothing.
///
/// The receipts the landing loop runs on are keyed to the commit they validated,
/// so a replay that rewrote an already-current branch would throw away a `verify`
/// that is still good — the lap would cost a CI run to prove what it had proven.
#[test]
fn an_already_current_branch_is_left_alone() {
    let (dir, repo) = init("rebase-current");
    let root: Files<'_> = &[("shared.txt", "base\n")];
    let base = commit(&repo, &[], root);
    let side: Files<'_> = &[("shared.txt", "base\n"), ("work.txt", "work\n")];
    let tip = commit(&repo, &[base], side);

    point(&dir, "refs/heads/main", base);
    point(&dir, "refs/heads/work", tip);
    materialise(&dir, side);

    let outcome = gitwrite::rebase(&dir, "refs/heads/work", "refs/heads/main").expect("rebase");
    assert_eq!(outcome, Rebase::Current);
    let still = repo
        .rev_parse_single("refs/heads/work")
        .expect("resolve work")
        .detach();
    assert_eq!(still, tip, "an already-current branch keeps its sha");
}

/// A replay drops a file, and the worktree stops carrying it.
///
/// A checkout ADDS and OVERWRITES; nothing in it removes, so this is the one
/// worktree effect that has to be written by hand and is therefore the one that
/// can be silently missing. Left undone, the next `verify` compiles a file that
/// is not in the commit.
#[test]
fn a_path_the_base_deleted_leaves_the_worktree() {
    let (dir, repo) = init("rebase-delete");
    let root: Files<'_> = &[("kept.txt", "kept\n"), ("doomed.txt", "doomed\n")];
    let base = commit(&repo, &[], root);

    // The trunk deletes `doomed.txt`.
    let trunk: Files<'_> = &[("kept.txt", "kept\n")];
    let moved = commit(&repo, &[base], trunk);

    // The branch touches something else entirely.
    let side: Files<'_> = &[
        ("kept.txt", "kept\n"),
        ("doomed.txt", "doomed\n"),
        ("work.txt", "work\n"),
    ];
    let tip = commit(&repo, &[base], side);

    point(&dir, "refs/heads/main", moved);
    point(&dir, "refs/heads/work", tip);
    materialise(&dir, side);

    let outcome = gitwrite::rebase(&dir, "refs/heads/work", "refs/heads/main").expect("rebase");
    assert!(
        matches!(outcome, Rebase::Replayed { .. }),
        "a delete on one side and an add on the other is not a conflict, got {outcome:?}"
    );
    assert!(
        !dir.join("doomed.txt").exists(),
        "the deleted path is still on disk"
    );
    assert!(
        dir.join("work.txt").is_file(),
        "the branch's own file survived"
    );
    let landed = repo
        .rev_parse_single("refs/heads/work")
        .expect("resolve work")
        .detach();
    assert!(
        !tree_names(&repo, landed).contains(&"doomed.txt".to_owned()),
        "the replayed tree still carries the deleted path"
    );
}

// --- unwinding a speculation (CLOUD-862, CLOUD-1456) --------------------------
//
// The two primitives the lap's bet settle is built on, driven over a real
// repository rather than over the driver — which is the same reason the header
// gives for reaching `land::record` instead of `land::replay`: the composition
// above them reads a lease over the network, and a case that needed one would be
// a test of the network rather than of the unwind.

/// **An ADOPTED bet unwinds by replaying this branch's OWN commits.**
///
/// The bet has no undo point — the process that recorded it died — so the range
/// bound and the graft point are two different commits, which is the whole reason
/// [`gitwrite::replay_onto`] exists beside `rebase`. The bound is the borrowed
/// base and the graft is the trunk, so `base..HEAD` is precisely what this branch
/// authored.
///
/// The load-bearing assertion is the NEGATIVE one: the holder's file must be gone
/// from the replayed tree. A `rebase` onto the trunk would land the borrowed
/// commits too and pass every other assertion here — which is exactly the state
/// CLOUD-862 measured reaching a push.
#[test]
fn an_adopted_bet_replays_only_this_branchs_own_commits() {
    let (dir, repo) = init("rebase-adopted-bet");
    let root: Files<'_> = &[("shared.txt", "base\n")];
    let base = commit(&repo, &[], root);

    // The holder's commit, which this tree was speculatively linearized onto.
    let borrowed: Files<'_> = &[("shared.txt", "base\n"), ("from-holder.txt", "theirs\n")];
    let holder = commit(&repo, &[base], borrowed);

    // Our own commit, sitting on top of the borrowed one.
    let speculative: Files<'_> = &[
        ("shared.txt", "base\n"),
        ("from-holder.txt", "theirs\n"),
        ("ours.txt", "ours\n"),
    ];
    let tip = commit(&repo, &[holder], speculative);

    point(&dir, "refs/heads/main", base);
    point(&dir, "refs/heads/work", tip);
    materialise(&dir, speculative);

    let outcome = gitwrite::replay_onto(
        &dir,
        "refs/heads/work",
        &holder.to_hex().to_string(),
        "refs/heads/main",
    )
    .expect("replay onto the trunk");
    let Rebase::Replayed { head, commits } = outcome else {
        panic!("the unwind must replay, got {outcome:?}");
    };
    assert_eq!(commits, 1, "only this branch's own commit was in the range");

    let landed = repo
        .rev_parse_single("refs/heads/work")
        .expect("resolve work")
        .detach();
    assert_eq!(landed.to_hex().to_string(), head);
    assert_eq!(
        repo.find_commit(landed)
            .expect("find replayed")
            .parent_ids()
            .map(gix::Id::detach)
            .collect::<Vec<_>>(),
        vec![base],
        "the unwound branch sits on the trunk rather than on the holder"
    );

    let names = tree_names(&repo, landed);
    assert!(
        !names.contains(&"from-holder.txt".to_owned()),
        "the borrowed commit came along, which is the state that must never push: {names:?}"
    );
    assert!(
        names.contains(&"ours.txt".to_owned()),
        "this branch's own work was dropped: {names:?}"
    );
    // And the WORKTREE, which is what the next lap's `verify` compiles.
    assert!(
        !dir.join("from-holder.txt").exists(),
        "the borrowed file is still on disk"
    );
    assert!(dir.join("ours.txt").is_file(), "our own file left the disk");
}

/// **A bet this process PLACED unwinds exactly, to the sha it recorded.**
///
/// Not a replay: the undo point is this branch's own last non-speculative HEAD,
/// so restoring it mints nothing and throws no receipt away. A replay here would
/// produce a new sha for identical work and cost a CI run to re-prove it.
#[test]
fn a_placed_bet_unwinds_to_the_recorded_sha() {
    let (dir, repo) = init("rebase-placed-bet");
    let root: Files<'_> = &[("shared.txt", "base\n")];
    let base = commit(&repo, &[], root);

    // The undo point: where this branch stood before anything was borrowed.
    let mine: Files<'_> = &[("shared.txt", "base\n"), ("ours.txt", "ours\n")];
    let undo = commit(&repo, &[base], mine);

    let speculative: Files<'_> = &[
        ("shared.txt", "base\n"),
        ("ours.txt", "ours\n"),
        ("from-holder.txt", "theirs\n"),
    ];
    let tip = commit(&repo, &[undo], speculative);

    point(&dir, "refs/heads/work", tip);
    materialise(&dir, speculative);

    let restored = gitwrite::reset_hard(&dir, "refs/heads/work", &undo.to_hex().to_string())
        .expect("reset to the undo point");
    assert_eq!(
        restored,
        undo.to_hex().to_string(),
        "the unwind lands on the EXACT recorded sha, minting nothing"
    );
    assert_eq!(
        repo.rev_parse_single("refs/heads/work")
            .expect("resolve work")
            .detach(),
        undo,
        "the ref did not move"
    );
    // The worktree is the half a ref-only assertion never reaches, and the
    // REMOVAL is the half a checkout does not do on its own.
    assert!(
        !dir.join("from-holder.txt").exists(),
        "the borrowed file survived the unwind"
    );
    assert!(dir.join("ours.txt").is_file(), "our own file was removed");
}

/// **A BET REACHES THE GATE'S ENVIRONMENT, and the publication is a function of
/// the bet rather than a side effect kept in step with it.**
///
/// `land::verify` is the one metered step a speculation has to be visible to: a
/// gate cannot otherwise tell a commit this branch authored from one the lap
/// adopted, and CLOUD-748 measured the consequence twice in one session — the
/// consumer's race check reported the waiter as racing the very PR the bet was
/// placed on.
///
/// Driven through `land::verify` over a real repository, because the thing under
/// test is whether the pairs SURVIVE the exec boundary. A case asserting that
/// `Bet::published` returns the base would pass over a `verify` that dropped
/// them on the floor, which is the whole class the second tier exists for.
#[test]
fn a_published_bet_reaches_the_gate_and_an_absent_one_publishes_nothing() {
    let (dir, repo) = init("verify-publication");
    let base = commit(&repo, &[], &[("shared.txt", "base\n")]);
    point(&dir, "refs/heads/work", base);
    // `verify` reads HEAD, and the other cases in this file never do — so the
    // fixture's initial branch has to exist as well as `work`. Both spellings,
    // because which one `gix::init` writes into HEAD is the host git's default
    // and not this case's to depend on.
    point(&dir, "refs/heads/main", base);
    point(&dir, "refs/heads/master", base);
    materialise(&dir, &[("shared.txt", "base\n")]);

    // A gate that passes only when the variable carries the expected value. The
    // gate is the assertion, so a dropped pair reddens the case rather than
    // leaving it to a follow-up read.
    let gate = dir.join("gate.sh");
    std::fs::write(
        &gate,
        format!(
            "#!/bin/sh\ntest \"${{{}}}\" = \"speculated-base\"\n",
            batten::speculation::PUBLISHED_AS
        ),
    )
    .expect("write the gate");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o755))
            .expect("make the gate runnable");
    }
    let command = vec![gate.to_string_lossy().into_owned()];

    let published = vec![(
        batten::speculation::PUBLISHED_AS.to_owned(),
        String::from("speculated-base"),
    )];
    assert!(
        matches!(
            batten::land::verify(&dir, "work", &command, &published).expect("run the gate"),
            batten::land::Verified::Clean(_)
        ),
        "the published pair did not reach the gate"
    );

    // THE MIRROR, and it is not hygiene: without it the case passes over a
    // boundary that publishes the variable unconditionally from some other
    // source, which would make a settled bet stay visible to every later gate.
    assert!(
        matches!(
            batten::land::verify(&dir, "work", &command, &[]).expect("run the gate"),
            batten::land::Verified::Refused(_)
        ),
        "the variable reached the gate with no bet outstanding"
    );
}

/// The filenames in a commit's tree.
fn tree_names(repo: &gix::Repository, id: gix::ObjectId) -> Vec<String> {
    let tree = repo
        .find_commit(id)
        .expect("find commit")
        .tree()
        .expect("tree");
    tree.iter()
        .filter_map(Result::ok)
        .map(|entry| entry.filename().to_string())
        .collect()
}
