//! Fixture suite for the extracted core primitives (CLOUD-36).
//!
//! These exercise the library surface directly rather than the compiled binary,
//! because the primitives mint no subcommand: they are substrate the Phase-2
//! commands consume, and the fixture suite under `mise run test` *is* their
//! gate (CLOUD-9, Option A). `tests/cli.rs` stays the place for anything a
//! consumer reaches over the CLI.
//!
//! The keystone is [`a_rebased_and_landed_branch_is_merged_though_ancestry_says_otherwise`]:
//! a "not landed" verdict on work that did land is silently wrong rather than
//! loudly broken, which is the failure class Batten exists to catch, so the
//! fixture set is as much the deliverable as the code is.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::cell::Cell;
use std::fs;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
#[expect(
    clippy::disallowed_types,
    reason = "stays, and test-only: this suite's fixtures assert on commit ordering, so they are built by the reference implementation with a monotonic clock"
)]
use std::process::Command;

use batten::error::UsageError;
use batten::git::{self, Evidence, Verdict, Window};

// --- the git fixture builder -------------------------------------------------

/// A hermetic scratch repository under `CARGO_TARGET_TMPDIR`.
struct Repo {
    dir: PathBuf,
    /// A monotonic second counter feeding the commit dates.
    clock: Cell<u32>,
}

/// A fresh repository at `CARGO_TARGET_TMPDIR/<name>`, wiped first so a crashed
/// prior run cannot mask behaviour.
fn repo(name: &str) -> Repo {
    let repo = Repo {
        dir: common::scratch(name),
        clock: Cell::new(0),
    };
    repo.git(&["init", "-q", "-b", "main"]);
    repo
}

impl Repo {
    /// Run git in the fixture and return its trimmed stdout, asserting success.
    ///
    /// Identity comes through `-c` rather than `git config`, so the fixture's
    /// own `.git/config` stays as bare as a fresh clone's. Global and system
    /// config are blanked: a developer's `commit.gpgsign` or `core.hooksPath`
    /// must not be able to break a fixture. `GIT_CEILING_DIRECTORIES` fences
    /// discovery to the test tmpdir, so a fixture that somehow lost its `.git`
    /// fails loudly instead of quietly answering about the real batten
    /// checkout — which lives above this directory.
    fn git(&self, args: &[&str]) -> String {
        let output = self.raw(args).output().expect("run git");
        assert!(
            output.status.success(),
            "git {args:?} failed in {}: {}",
            self.dir.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git stdout is UTF-8")
            .trim_end()
            .to_owned()
    }

    /// Run git for its exit status alone — the reachability oracle the keystone
    /// fixture needs, which by design has no caller in `src/`.
    fn try_git(&self, args: &[&str]) -> bool {
        self.raw(args).status().expect("run git").success()
    }

    #[expect(
        clippy::disallowed_types,
        reason = "stays, and test-only: it extends `common::git_command`'s fixture spawn with this suite's own commit clock"
    )]
    fn raw(&self, args: &[&str]) -> Command {
        // Identity, blanked global/system config and the `GIT_CEILING_DIRECTORIES`
        // fence all come from the one materializer (CLOUD-63). Only the
        // monotonic commit clock is this suite's own: fixtures here assert on
        // commit ordering, which needs stamps nothing else does.
        let stamp = format!("2020-01-01T00:00:{:02}Z", self.clock.get());
        let mut command = common::git_command(&self.dir, args);
        command
            .env("GIT_AUTHOR_DATE", &stamp)
            .env("GIT_COMMITTER_DATE", &stamp);
        command
    }

    fn write(&self, path: &str, body: &str) {
        let full = self.dir.join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("create fixture parent dir");
        }
        fs::write(full, body).expect("write fixture file");
    }

    fn write_bytes(&self, path: &str, body: &[u8]) {
        fs::write(self.dir.join(path), body).expect("write fixture bytes");
    }

    /// Stage everything and commit, returning the full SHA.
    ///
    /// The clock advances on every commit, and that is load-bearing rather than
    /// cosmetic: replaying a commit onto the same parent with the same tree,
    /// message *and* date produces the byte-identical object, which would
    /// silently turn the keystone fixture into a case ancestry gets right.
    fn commit(&self, message: &str) -> String {
        self.tick();
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "--allow-empty", "-m", message]);
        self.head()
    }

    fn tick(&self) {
        self.clock.set(self.clock.get() + 1);
    }

    fn head(&self) -> String {
        self.git(&["rev-parse", "HEAD"])
    }

    /// Replay `commit` onto the current branch — the "landed under a new SHA"
    /// move that a rebase, a cherry-pick, and a fast-forward landing all
    /// perform.
    fn replay(&self, commit: &str) -> String {
        self.tick();
        self.git(&["cherry-pick", commit]);
        self.head()
    }

    fn landing(&self, target: &str, head: &str) -> git::Landing {
        git::landing(&self.dir, target, head, Window::DEFAULT).expect("compute landing")
    }
}

/// The base every fixture starts from: `main` with one root commit.
fn seeded(name: &str) -> Repo {
    let repo = repo(name);
    repo.write("base.txt", "base\n");
    repo.commit("chore: base");
    repo
}

// --- merged-ness -------------------------------------------------------------

#[test]
fn a_rebased_and_landed_branch_is_merged_though_ancestry_says_otherwise() {
    // THE KEYSTONE (CLOUD-36). A branch is cut, `main` moves on, the work is
    // replayed onto the new tip and lands — the ordinary shape of every
    // fast-forward landing in this repo. The branch ref still points at the
    // pre-replay commit, which is not reachable from `main` and never will be.
    //
    // Ancestry therefore answers "never landed" about work that is sitting on
    // `main` right now. Patch identity answers correctly, because the *change*
    // survived the rewrite even though the SHA did not.
    let repo = seeded("landed-rebased");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "the work\n");
    let before_rebase = repo.commit("feat: the work");

    repo.git(&["checkout", "-q", "main"]);
    repo.write("other.txt", "unrelated\n");
    repo.commit("chore: main moves on");
    let landed_as = repo.replay(&before_rebase);

    assert_ne!(
        before_rebase, landed_as,
        "the fixture must actually rewrite the commit, or it proves nothing"
    );
    assert!(
        !repo.try_git(&["merge-base", "--is-ancestor", &before_rebase, "main"]),
        "ancestry says this branch never landed — that is the bug this primitive exists to \
         prevent, and if this assertion ever fails the fixture has stopped exercising it"
    );

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::Landed);
    assert!(landing.is_landed());
    assert!(landing.unlanded().is_empty());
    assert_eq!(landing.commits.len(), 1);
    assert_eq!(
        landing.commits[0]
            .evidence
            .as_ref()
            .unwrap()
            .target_commit(),
        Some(landed_as.as_str()),
        "the verdict names the commit on main that carries the change"
    );
}

#[test]
fn a_squash_merged_branch_is_merged_by_its_cumulative_content() {
    // A squash collapses N commits into one whose patch is the union of theirs,
    // so it matches none of them individually — per-commit identity is blind to
    // it, and the cumulative diff is the only thing that can see it.
    let repo = seeded("landed-squash");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "first\n");
    repo.commit("feat: first");
    repo.write("g.txt", "second\n");
    repo.commit("feat: second");

    repo.git(&["checkout", "-q", "main"]);
    repo.tick();
    repo.git(&["merge", "--squash", "feature"]);
    let squashed = repo.commit("feat: the whole branch, squashed");

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::Landed);
    assert_eq!(
        landing
            .cumulative_evidence
            .as_ref()
            .unwrap()
            .target_commit(),
        Some(squashed.as_str())
    );
    // The report must not lie about *how*: no individual commit landed.
    assert_eq!(landing.commits.len(), 2);
    for commit in &landing.commits {
        assert!(commit.evidence.is_none());
    }
}

#[test]
fn a_cherry_picked_commit_is_merged_under_a_different_sha() {
    let repo = seeded("landed-cherry-pick");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "picked\n");
    let original = repo.commit("feat: picked");

    repo.git(&["checkout", "-q", "main"]);
    let picked = repo.replay(&original);
    assert_ne!(original, picked);

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::Landed);
    // The equality that decided it is on patch identity, not on the SHA.
    let evidence = landing.commits[0].evidence.as_ref().unwrap();
    match evidence {
        Evidence::PatchId { patch_id, .. } => {
            assert_eq!(Some(patch_id), landing.commits[0].patch_id.as_ref());
        }
        other => panic!("expected patch-identity evidence, got {other:?}"),
    }
}

#[test]
fn an_unlanded_branch_is_not_reported_as_merged() {
    // The true negative. Over-reporting is its own silent failure — a gate that
    // calls everything landed gates nothing.
    let repo = seeded("unlanded");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "not landed anywhere\n");
    repo.commit("feat: outstanding");

    repo.git(&["checkout", "-q", "main"]);
    repo.write("other.txt", "unrelated\n");
    repo.commit("chore: unrelated");

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::NotLandedWithinWindow);
    assert!(!landing.is_landed());
    assert_eq!(landing.unlanded().len(), 1);
    assert!(landing.commits[0].evidence.is_none());
    assert!(
        !landing.scanned.target_truncated,
        "the whole target was searched, so this negative is actually proven"
    );
}

#[test]
fn a_partially_landed_branch_names_which_commits_landed() {
    let repo = seeded("landed-partial");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "first\n");
    let first = repo.commit("feat: first");
    repo.write("g.txt", "second\n");
    repo.commit("feat: second");

    repo.git(&["checkout", "-q", "main"]);
    repo.replay(&first);

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::PartiallyLanded);
    assert!(!landing.is_landed());
    // Oldest first, so the landed one is reported first.
    assert!(landing.commits[0].evidence.is_some());
    assert!(landing.commits[1].evidence.is_none());
    assert!(landing.cumulative_evidence.is_none());
    assert_eq!(landing.unlanded(), vec![landing.commits[1].commit.as_str()]);
}

#[test]
fn a_branch_that_changes_nothing_has_nothing_to_land() {
    // An empty patch has no identity at all — `git patch-id` prints nothing for
    // it. That is what keeps two unrelated empty commits from "matching" each
    // other, which is the shape a naive `Option` comparison gets wrong.
    let repo = seeded("landed-empty");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.commit("chore: empty");

    repo.git(&["checkout", "-q", "main"]);
    repo.commit("chore: also empty");

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::NothingToLand);
    assert!(
        landing.is_landed(),
        "a branch with nothing to land is not outstanding work"
    );
    assert!(landing.cumulative.is_none());
    assert_eq!(landing.commits.len(), 1);
    assert!(landing.commits[0].patch_id.is_none());
    assert_eq!(
        landing.commits[0].evidence,
        Some(Evidence::NoContent),
        "the target's own empty commit must not become evidence"
    );
}

#[test]
fn a_branch_the_target_already_contains_has_nothing_to_land() {
    // The fast-forward shape: `main` was advanced to the branch, so nothing on
    // it is outstanding. `NothingToLand` rather than `Landed` — there is no
    // *unlanded* content to have evidence about — and `is_landed()` accepts it,
    // which is why a consumer must not match on `Landed` alone.
    let repo = seeded("landed-fast-forward");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "the work\n");
    repo.commit("feat: the work");
    repo.git(&["checkout", "-q", "main"]);
    repo.git(&["merge", "-q", "--ff-only", "feature"]);

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::NothingToLand);
    assert!(landing.is_landed());
    assert!(landing.commits.is_empty());
    assert!(landing.unlanded().is_empty());
}

#[test]
fn cumulative_evidence_means_one_commit_over_there_not_a_squash_ritual() {
    // The field is "the branch's whole change is a single commit on the
    // target", which a one-commit branch satisfies trivially. Pinned because a
    // consumer reading it as "someone ran a squash merge" would be wrong here,
    // and the per-commit evidence is what actually answers that.
    let repo = seeded("landed-cumulative-single");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "the work\n");
    let original = repo.commit("feat: the work");
    repo.git(&["checkout", "-q", "main"]);
    let landed_as = repo.replay(&original);

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::Landed);
    assert_eq!(
        landing
            .cumulative_evidence
            .as_ref()
            .and_then(Evidence::target_commit),
        Some(landed_as.as_str())
    );
    assert!(
        landing.commits[0].evidence.is_some(),
        "the commit survived intact, which is the question `evidence` answers"
    );
}

#[test]
fn a_change_and_its_revert_leave_nothing_to_land() {
    let repo = seeded("landed-reverted");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "added\n");
    let added = repo.commit("feat: add");
    repo.tick();
    repo.git(&["revert", "--no-edit", &added]);

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::NothingToLand);
    assert!(landing.cumulative.is_none());
}

#[test]
fn work_that_landed_through_a_merge_commit_is_still_merged() {
    // `git log -p` prints nothing for a merge commit, which is correct here
    // rather than a gap: a real merge brings its side commits into the target's
    // own history, and those are enumerated individually. This fixture pins
    // that, so a future `--first-parent` "optimisation" — which would make
    // everything merged in invisible — fails loudly.
    let repo = seeded("landed-merge");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "the work\n");
    let original = repo.commit("feat: the work");

    repo.git(&["checkout", "-q", "-b", "pr", "main"]);
    let on_pr = repo.replay(&original);
    repo.git(&["checkout", "-q", "main"]);
    repo.tick();
    repo.git(&["merge", "--no-ff", "-q", "-m", "merge: pr", "pr"]);

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.verdict, Verdict::Landed);
    assert_eq!(
        landing.commits[0]
            .evidence
            .as_ref()
            .unwrap()
            .target_commit(),
        Some(on_pr.as_str()),
        "the evidence is the side commit, not the merge"
    );
}

#[test]
fn a_landing_older_than_the_window_is_unproven_rather_than_absent() {
    // The executable form of "a false not-landed is the failure class": when
    // the window cannot reach the landing, the answer says so instead of
    // asserting an absence it did not prove.
    let repo = seeded("landed-window");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write("f.txt", "the work\n");
    let original = repo.commit("feat: the work");

    repo.git(&["checkout", "-q", "main"]);
    repo.replay(&original);
    for n in 0..5 {
        repo.write("churn.txt", &format!("{n}\n"));
        repo.commit("chore: churn");
    }

    let narrow = git::landing(
        &repo.dir,
        "main",
        "feature",
        Window::of(NonZeroUsize::new(2).unwrap()),
    )
    .expect("compute landing");
    assert_eq!(narrow.verdict, Verdict::NotLandedWithinWindow);
    assert!(
        narrow.scanned.target_truncated,
        "older history went unexamined, and the answer must admit it"
    );
    assert_eq!(narrow.scanned.target_commits_scanned, 2);

    // Widened, the same repository answers correctly — so the narrow verdict
    // was a limit of the search, exactly as it claimed.
    assert_eq!(repo.landing("main", "feature").verdict, Verdict::Landed);
}

#[test]
fn the_cumulative_and_per_commit_identities_agree_across_a_rename() {
    // `diff.renames` defaults true for the porcelain diff used on the
    // cumulative side and false for plumbing. Unpinned, the two generators
    // disagree about any commit that renames a file and a real landing goes
    // unrecognised — a silently wrong answer with no visible symptom. This is
    // the invariant test that catches drift between them.
    let repo = seeded("landed-rename");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.git(&["mv", "base.txt", "renamed.txt"]);
    repo.write("renamed.txt", "base\nand edited\n");
    repo.commit("refactor: rename and edit");

    let landing = repo.landing("main", "feature");
    assert_eq!(landing.commits.len(), 1);
    assert_eq!(
        landing.cumulative, landing.commits[0].patch_id,
        "one-commit branch: the cumulative identity IS the commit's identity"
    );
}

#[test]
fn a_binary_change_is_not_confused_with_a_different_binary_change() {
    // Without `--binary` every binary change renders as the same
    // "Binary files … differ" line, so two unrelated edits to one path share an
    // identity and either is reported as the other's landing.
    let repo = seeded("landed-binary");
    repo.write_bytes("blob.bin", &[0u8, 1, 2, 3, 0xff]);
    repo.commit("chore: seed the blob");

    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.write_bytes("blob.bin", &[0u8, 1, 2, 3, 0xfe]);
    repo.commit("feat: change the blob one way");

    repo.git(&["checkout", "-q", "main"]);
    repo.write_bytes("blob.bin", &[9u8, 9, 9, 9, 0x11]);
    repo.commit("chore: change the blob another way");

    let landing = repo.landing("main", "feature");
    assert_eq!(
        landing.verdict,
        Verdict::NotLandedWithinWindow,
        "a different change to the same binary path is not this change landing"
    );
}

#[test]
fn a_branch_with_no_common_history_is_a_usage_error() {
    let repo = seeded("landed-orphan");
    repo.git(&["checkout", "-q", "--orphan", "feature"]);
    repo.write("f.txt", "unrelated history\n");
    repo.commit("feat: orphan");

    let err = git::landing(&repo.dir, "main", "feature", Window::DEFAULT).unwrap_err();
    assert!(
        err.downcast_ref::<UsageError>().is_some(),
        "no common history is bad input, not an internal failure"
    );
}

#[test]
fn an_unresolvable_ref_is_a_usage_error() {
    let repo = seeded("landed-bad-ref");
    for (target, head) in [("main", "no-such-branch"), ("no-such-branch", "main")] {
        let err = git::landing(&repo.dir, target, head, Window::DEFAULT).unwrap_err();
        assert!(
            err.downcast_ref::<UsageError>().is_some(),
            "an unresolvable ref is bad input, not an internal failure"
        );
    }
}

#[test]
fn the_answer_is_byte_stable_and_independent_of_where_the_repo_lives() {
    let build = |name: &str| {
        let repo = seeded(name);
        repo.git(&["checkout", "-q", "-b", "feature"]);
        repo.write("f.txt", "the work\n");
        let original = repo.commit("feat: the work");
        repo.git(&["checkout", "-q", "main"]);
        repo.replay(&original);
        repo
    };

    let repo = build("stable-a");
    let first = repo.landing("main", "feature");
    let second = repo.landing("main", "feature");
    assert_eq!(first, second, "identical repo state, identical answer");
    assert_eq!(format!("{first:?}"), format!("{second:?}"));

    // Patch identity is a function of content, so the same history built at a
    // different path produces the same identities.
    let elsewhere = build("stable-b");
    let there = elsewhere.landing("main", "feature");
    assert_eq!(
        first.commits[0].patch_id, there.commits[0].patch_id,
        "patch identity must not depend on where the repository is checked out"
    );
    assert_eq!(first.cumulative, there.cumulative);
}

// --- counted suppression markers, driven by config ---------------------------

/// A fixture `batten.toml` declaring markers and verbs, parsed through the real
/// loader.
///
/// Every assertion below reads its vocabulary out of *this text* and never out
/// of a literal in the test body — which is the whole point: if the tables were
/// baked into the crate, changing this fixture would not change the answers.
const TABLES: &str = r#"
version = 1

[[marker]]
id = "waiver"
token = "POLICY-WAIVER"

[[marker]]
id = "scoped-waiver"
token = "SCOPED-WAIVER"
glob = "src/**/*.txt"

[[verb]]
verb = "obliterate"
effect = "destructive"
redirect = "use the write surface"

[[verb]]
verb = "clobber"
effect = "write"
"#;

fn tables() -> batten::config::Config {
    batten::config::parse(TABLES, "fixture batten.toml").expect("fixture config parses")
}

#[test]
fn suppression_marker_counts_come_from_config_not_from_the_crate() {
    let config = tables();
    let repo = repo("markers-counted");
    // The tokens written into the tree are read out of the parsed config, so
    // this fixture cannot pass against a crate that hardcodes its own.
    let waiver = &config.markers[0];
    let scoped = &config.markers[1];

    repo.write(
        "src/a.txt",
        &format!(
            "clean\n{} first\nclean\n{} second\n",
            waiver.token, waiver.token
        ),
    );
    repo.write("src/b.txt", &format!("{} here\n", scoped.token));
    // Outside the scoped marker's glob: the whole-tree marker sees it, the
    // scoped one must not.
    repo.write(
        "elsewhere.txt",
        &format!("{} {}\n", waiver.token, scoped.token),
    );

    let hits = batten::markers::find(&repo.dir, &config.markers).expect("scan for markers");
    let counts = batten::markers::counts(&config.markers, &hits);
    assert_eq!(
        counts.get(&waiver.id),
        Some(&3),
        "two occurrences in one file plus one elsewhere"
    );
    assert_eq!(
        counts.get(&scoped.id),
        Some(&1),
        "the glob narrows the scoped marker to src/"
    );
}

#[test]
fn marker_hits_are_pointers_and_never_the_matched_line() {
    // Non-negotiable rule 4: a suppression comment is exactly the kind of text
    // that quotes the thing being suppressed.
    let config = tables();
    let repo = repo("markers-pointer-only");
    let secret = "the-line-body-nobody-should-see";
    repo.write(
        "src/a.txt",
        &format!("{} {secret}\n", config.markers[0].token),
    );

    let hits = batten::markers::find(&repo.dir, &config.markers).expect("scan for markers");
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].path, "src/a.txt");
    assert_eq!(hits[0].line, 1);
    assert_eq!(hits[0].marker, config.markers[0].id);
    let rendered = format!("{hits:?}");
    assert!(
        !rendered.contains(secret),
        "a hit must carry path:line and the marker id, never the bytes"
    );
}

#[test]
fn marker_scanning_is_byte_stable_and_skips_binaries() {
    let config = tables();
    let repo = repo("markers-stable");
    let token = &config.markers[0].token;
    for name in ["src/z.txt", "src/a.txt", "src/m.txt"] {
        repo.write(name, &format!("{token}\n{token}\n"));
    }
    // A binary file cannot hold a marker an author typed, and must not abort
    // the scan either.
    repo.write_bytes("src/blob.txt", &[0u8, 159, 146, 150]);

    let first = batten::markers::find(&repo.dir, &config.markers).expect("scan");
    let second = batten::markers::find(&repo.dir, &config.markers).expect("scan again");
    assert_eq!(first, second, "identical tree, identical hits");
    assert_eq!(first.len(), 6);
    let order: Vec<(&str, usize)> = first
        .iter()
        .map(|hit| (hit.path.as_str(), hit.line))
        .collect();
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(order, sorted, "hits come back sorted by path then line");
}

#[test]
fn no_markers_configured_finds_nothing() {
    // Cheap when irrelevant (house-style §4), and a repo with no marker config
    // must not be reported as suppression-free-by-accident either — zero
    // markers configured means zero counts, and `counts` says so explicitly.
    let repo = repo("markers-none");
    repo.write("a.txt", "anything at all\n");
    assert!(
        batten::markers::find(&repo.dir, &[])
            .expect("scan")
            .is_empty()
    );
    assert!(batten::markers::counts(&[], &[]).is_empty());
}

// --- the mutating-verb table, driven by config -------------------------------

#[test]
fn the_mutating_verb_table_is_config_driven() {
    let config = tables();
    batten::verbs::validate(&config.verbs).expect("the fixture table is well formed");

    // Both verbs are known only because the fixture config declares them.
    let destructive = &config.verbs[0];
    let write = &config.verbs[1];
    assert_eq!(
        batten::verbs::classify(&config.verbs, &destructive.verb),
        Some(destructive)
    );
    assert_eq!(
        batten::verbs::classify(&config.verbs, &write.verb),
        Some(write)
    );
    assert_eq!(
        destructive.redirect.as_deref(),
        Some("use the write surface"),
        "the deny message's redirect is declared beside the verb, not in the crate"
    );
}

#[test]
fn an_undeclared_program_is_not_classified_as_mutating() {
    let config = tables();
    assert_eq!(
        batten::verbs::classify(&config.verbs, "a-program-the-config-never-named"),
        None,
        "absence of information, which a consumer reads conservatively (§5)"
    );
}

#[test]
fn verbs_are_partitioned_by_the_one_effect_vocabulary() {
    // The severity axis is house-style §5's, not a second one minted here, so
    // `destructive` here means what it means everywhere else in the tool.
    let config = tables();
    let destructive =
        batten::verbs::with_effect(&config.verbs, batten::effect::Effect::Destructive);
    let write = batten::verbs::with_effect(&config.verbs, batten::effect::Effect::Write);
    assert_eq!(destructive.len(), 1);
    assert_eq!(write.len(), 1);
    assert_ne!(destructive[0].verb, write[0].verb);
}

#[test]
fn a_marker_that_cannot_be_counted_is_refused_at_load() {
    // The sibling of the verb table, and the sibling of its defect (CLOUD-253):
    // both shipped in one commit, CLOUD-242 wired one of them into `parse`, and
    // this one kept a validator whose only caller was `markers::find` — which
    // has no caller in `src/` at all. Every refusal below could not fire.
    //
    // Asserted through `parse` for the same reason that fix names: reaching past
    // it to call the validator by hand proves the validator works while hiding
    // that loading never invokes it, which is how a green suite certified a
    // refusal production never performed.
    let empty_token = "version = 1\n\n[[marker]]\nid = \"waiver\"\ntoken = \"\"\n";
    let err = batten::config::parse(empty_token, "fixture").unwrap_err();
    assert!(
        err.downcast_ref::<UsageError>().is_some(),
        "an empty token matches every line of every file"
    );

    let empty_id = "version = 1\n\n[[marker]]\nid = \"\"\ntoken = \"WAIVED\"\n";
    let err = batten::config::parse(empty_id, "fixture").unwrap_err();
    assert!(err.downcast_ref::<UsageError>().is_some());

    let empty_glob = "version = 1\n\n[[marker]]\nid = \"w\"\ntoken = \"WAIVED\"\nglob = \"\"\n";
    let err = batten::config::parse(empty_glob, "fixture").unwrap_err();
    assert!(
        err.downcast_ref::<UsageError>().is_some(),
        "an empty glob reads as everywhere and selects nothing"
    );

    // Two rows under one id make a count that answers no question.
    let twice = "version = 1\n\n[[marker]]\nid = \"w\"\ntoken = \"A\"\n\n[[marker]]\nid = \"w\"\ntoken = \"B\"\n";
    let err = batten::config::parse(twice, "fixture").unwrap_err();
    assert!(err.downcast_ref::<UsageError>().is_some());

    // The other direction, so the refusal is not merely "any marker table
    // fails": a well-formed table still loads.
    let valid = "version = 1\n\n[[marker]]\nid = \"w\"\ntoken = \"WAIVED\"\n";
    let config = batten::config::parse(valid, "fixture").expect("a valid marker table loads");
    assert_eq!(config.markers.len(), 1);
}

#[test]
fn a_verb_table_that_would_be_inert_is_refused_at_load() {
    // A `read` row in the mutating-verb table matches nothing while reading as
    // covered. Refused at parse, never kept.
    //
    // This test now earns its name. It used to `expect` `parse` to SUCCEED and
    // then call `verbs::validate` by hand — which proved the validator worked
    // while demonstrating that loading never invoked it, so a green suite
    // certified a refusal production never performed (CLOUD-242).
    let inert = "version = 1\n\n[[verb]]\nverb = \"x\"\neffect = \"read\"\n";
    let err = batten::config::parse(inert, "fixture").unwrap_err();
    assert!(err.downcast_ref::<UsageError>().is_some());

    // Same for a verb declared twice: one verb, one effect, one redirect.
    let twice = "version = 1\n\n[[verb]]\nverb = \"x\"\neffect = \"write\"\n\n[[verb]]\nverb = \"x\"\neffect = \"write\"\n";
    let err = batten::config::parse(twice, "fixture").unwrap_err();
    assert!(err.downcast_ref::<UsageError>().is_some());

    // And the other direction, so the refusal is not merely "any verb table
    // fails": a well-formed table still loads.
    let valid = "version = 1\n\n[[verb]]\nverb = \"rm\"\neffect = \"destructive\"\n";
    let config = batten::config::parse(valid, "fixture").expect("a valid verb table loads");
    assert_eq!(config.verbs.len(), 1);

    let unknown = "version = 1\n\n[[verb]]\nverb = \"x\"\neffect = \"nonsense\"\n";
    let err = batten::config::parse(unknown, "fixture").unwrap_err();
    assert!(
        err.downcast_ref::<UsageError>().is_some(),
        "an effect outside the vocabulary is bad config, not an internal failure"
    );
}

// --- composition with the primitives that already landed ---------------------

#[test]
fn state_paths_resolve_through_the_one_repo_root_finder() {
    // Out-of-tree state paths are CLOUD-38's resolver, reused rather than
    // rebuilt: `git::repo_root` (CLOUD-34) feeds `state::repo_state_dir`, and
    // the source-level gates in `git.rs` are what keep a second implementation
    // of either from appearing.
    let repo = seeded("state-composition");
    let nested = repo.dir.join("crates").join("thing");
    fs::create_dir_all(&nested).expect("create nested dir");

    let root = git::repo_root(&nested).expect("resolve the repo root");
    let state = batten::state::repo_state_dir(&root).expect("resolve the state dir");
    let segment = state
        .file_name()
        .and_then(|name| name.to_str())
        .expect("the state dir has a segment");
    // Led by the repository's own directory name, not equal to it: CLOUD-296
    // appended a per-checkout digest so two clones sharing a directory name
    // cannot share a store. The prefix is what keeps the segment DERIVED from
    // the repository at runtime rather than baked in, which is what this
    // composition case is about.
    assert!(
        segment.starts_with("state-composition-"),
        "the repo segment is derived from the repository at runtime, got {segment}"
    );
    assert!(
        !state.starts_with(&repo.dir),
        "state lives out of tree, so a checkout stays clean"
    );
}

#[test]
fn the_acceptance_runner_is_the_landed_rule_engine() {
    // "The acceptance runner" in CLOUD-36's list is not new code: an acceptance
    // item is a named command with an exit code and no classification step, and
    // that is the `command` rule kind on the engine CLOUD-12 landed (CLOUD-47
    // was cancelled as subsumed). This asserts the composition rather than
    // minting a second runner — the read-effect half runs the non-spawning
    // kinds and *refuses* the rest loudly, which is what keeps a skipped gate
    // from exiting 0.
    let config = batten::config::parse(
        "version = 1\n\n[[rule]]\nid = \"acceptance\"\nkind = \"command\"\nglob = \"**/*.txt\"\n\
         check = \"true\"\nseverity = \"deny\"\n",
        "fixture",
    )
    .expect("fixture config parses");
    let repo = repo("acceptance-runner");
    repo.write("a.txt", "content\n");

    let err = batten::rules::run_static(
        &config.rules,
        &config.provisions,
        &config.patterns,
        &repo.dir,
    )
    .unwrap_err();
    assert!(
        err.downcast_ref::<UsageError>().is_some(),
        "the read-effect surface refuses a spawning rule loudly, never skips it"
    );
    assert!(
        batten::rules::run_all(
            &config.rules,
            &config.provisions,
            &config.patterns,
            &repo.dir
        )
        .expect("the spawning surface runs it")
        .findings
        .is_empty(),
        "an acceptance item that exits 0 produces no finding"
    );
}

#[test]
fn the_published_schema_takes_the_effect_vocabulary_from_one_place() {
    // `Effect` hand-writes Serialize/Deserialize/JsonSchema, so three
    // spellings of the vocabulary could drift apart. All three read
    // `Effect::ALL`, and this asserts the committed schema still shows exactly
    // that list — a consumer validating `batten.toml` against the published
    // schema must accept precisely what the loader accepts, no more and no less.
    let schema: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../schema/batten.schema.json"),
        )
        .expect("read the committed schema"),
    )
    .expect("the committed schema is JSON");

    let published: Vec<&str> = schema["$defs"]["Effect"]["enum"]
        .as_array()
        .expect("the schema defines the Effect vocabulary")
        .iter()
        .map(|token| token.as_str().expect("tokens are strings"))
        .collect();
    let declared: Vec<&str> = batten::effect::Effect::ALL
        .iter()
        .map(|effect| effect.as_str())
        .collect();
    assert_eq!(published, declared);
    for token in &published {
        assert!(
            batten::effect::Effect::from_token(token).is_some(),
            "the schema publishes {token:?}, which the loader would refuse"
        );
    }
}

#[test]
fn the_crate_bakes_in_no_consumer_vocabulary() {
    // Non-negotiable rule 1, over the whole library: every token this fixture
    // config declares is a consumer's word, and a grep of `crates/batten/src`
    // for any of them must return zero hits. The tables are config; the core
    // knows only their shape.
    let config = tables();
    let vocabulary: Vec<String> = config
        .markers
        .iter()
        .map(|marker| marker.token.clone())
        .chain(config.verbs.iter().map(|verb| verb.verb.clone()))
        .collect();

    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut scanned = 0;
    for entry in fs::read_dir(&src).expect("read src/") {
        let path = entry.expect("read dir entry").path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            continue;
        }
        scanned += 1;
        let source = fs::read_to_string(&path).expect("read source");
        for token in &vocabulary {
            assert!(
                !source.contains(token),
                "{}: contains the consumer token {token:?}; consumer-specific tables live in \
                 batten.toml, never in crates/batten (non-negotiable rule 1)",
                path.display()
            );
        }
    }
    assert!(scanned > 0, "the grep must actually have read the crate");
}

// --- warm-fork identity requirements (CLOUD-83) --------------------------------
//
// The library half of the restart obligations. `tests/cli.rs` covers what a
// consumer reaches over the CLI — the resume point and the lineage record — and
// these cover the two identity properties, which mint no subcommand: the
// sequence kind's session must follow a fork, and the other three kinds must
// carry no session at all.

/// A scratch store directory, wiped so a crashed prior run cannot mask anything.
fn session_store(name: &str) -> PathBuf {
    common::scratch(name)
}

/// Record a chain `keys[0]` <- `keys[1]` <- …, each declaring the one before it
/// as its parent, the way a run of separate forked processes would.
fn fork_chain(dir: &Path, keys: &[&str]) {
    for pair in keys.windows(2) {
        batten::session::observe(
            dir,
            &batten::session::Declared {
                key: pair[1].to_owned(),
                parent: Some(pair[0].to_owned()),
            },
        )
        .expect("record a fork edge");
    }
}

#[test]
fn a_sequence_finding_open_at_fork_time_follows_the_fork() {
    // CLOUD-83's §7 (b) and the identity half of its stated assumption: a warm
    // fork continues the parent's session key, so the deny-then-bypass finding
    // the parent opened keeps its identity in the trajectory that inherited the
    // working state. Asserted over `sequence_fingerprint` itself, because the
    // claim is about the identity and not about any rendering of it.
    let dir = session_store("fork-identity");
    fork_chain(&dir, &["alpha", "beta", "gamma"]);

    let opened = batten::identity::sequence_fingerprint("deny-then-bypass", "p", Some("alpha"));
    for descendant in ["beta", "gamma"] {
        let resolved =
            batten::session::sequence_session(&dir, descendant).expect("resolve the lineage");
        assert_eq!(
            batten::identity::sequence_fingerprint("deny-then-bypass", "p", Some(&resolved)),
            opened,
            "{descendant} inherited the working state, so it inherits the open finding"
        );
    }

    // The other direction is what makes it a fork rule rather than
    // session-blindness: an unrelated session mints its OWN identity, which is
    // the entire reason the session is in the tuple.
    let stranger =
        batten::session::sequence_session(&dir, "stranger").expect("resolve an unforked session");
    assert_ne!(
        batten::identity::sequence_fingerprint("deny-then-bypass", "p", Some(&stranger)),
        opened,
        "a second session's incident must not dedupe into the first's open finding"
    );
}

#[test]
fn no_session_scoped_field_enters_a_code_log_or_scope_identity() {
    // CLOUD-83's §7 (d). These three kinds survive a restart by CONSTRUCTION —
    // their tuples carry nothing process-local — and that is a property worth a
    // gate rather than a comment, because the cost of losing it is silent: every
    // stored finding would re-mint under a new identity on the next fork and the
    // store would look busy rather than broken.
    //
    // Asserted twice. First behaviourally: the three functions take no session,
    // so a caller cannot vary one, and a store with a lineage recorded in it
    // changes none of the three values.
    let dir = session_store("fork-identity-audit");
    let code = batten::identity::code_fingerprint(
        "r",
        "src/a.rs",
        "TODO",
        batten::identity::SpanNormalization::Collapsed,
    )
    .expect("a clean repo-relative path");
    let log = batten::identity::log_fingerprint("r", "stdout", "template");
    let scope = batten::identity::scope_fingerprint("r", "src/a.rs");

    fork_chain(&dir, &["alpha", "beta"]);
    assert_eq!(
        batten::identity::code_fingerprint(
            "r",
            "src/a.rs",
            "TODO",
            batten::identity::SpanNormalization::Collapsed,
        )
        .expect("a clean repo-relative path"),
        code,
        "a code identity is a fact about content, not about who was looking"
    );
    assert_eq!(
        batten::identity::log_fingerprint("r", "stdout", "template"),
        log
    );
    assert_eq!(batten::identity::scope_fingerprint("r", "src/a.rs"), scope);

    // The sequence kind is the control: it DOES move with the session, so a
    // suite that only asserted the three above would also pass if every
    // fingerprint had quietly become session-blind.
    assert_ne!(
        batten::identity::sequence_fingerprint("r", "p", Some("alpha")),
        batten::identity::sequence_fingerprint("r", "p", Some("beta")),
        "the sequence kind must still distinguish sessions"
    );

    // Second, at the source level, in the spirit of `store.rs`'s
    // `source_keys_on_no_basename`: the behavioural half above cannot fail while
    // the signatures stay session-free, so it would not catch the change that
    // matters — someone adding a session parameter. Each function BODY is
    // bounded by the first column-zero `}`, which is where an item ends under
    // this crate's formatting.
    // Normalized, and terminated by `split_once` rather than by `next()`, for
    // the reason `identity.rs`'s own copy of this idiom now states at length
    // (CLOUD-612): `read_to_string` does no line-ending translation, so a CRLF
    // checkout leaves `"\n}\n"` matching nothing, and `next()` answers that
    // with the whole rest of the file instead of with an error. This site is
    // the same defect one target further on — it never ran on Windows, because
    // cargo stopped at the `--lib` failure before reaching the integration
    // tests.
    let source =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/identity.rs"))
            .expect("read identity.rs")
            .replace("\r\n", "\n");
    for name in [
        "pub fn code_fingerprint",
        "pub fn log_fingerprint",
        "pub fn scope_fingerprint",
    ] {
        let Some((body, _)) = source
            .split_once(name)
            .and_then(|(_, rest)| rest.split_once("\n}\n"))
        else {
            panic!("{name} is in identity.rs, and its body ends at a column-zero `}}`")
        };
        assert!(
            !body.contains("session"),
            "{name} reads a session; a process-local component in a code/log/scope \
             tuple would re-mint every stored finding on a warm fork (CLOUD-83)"
        );
    }
}

// --- CLOUD-249: a permission drop is a premise, and a premise gets asserted --

/// The drop-to-`0o000` needle, assembled by concatenation so this file's own
/// fixtures — which have to carry the literal text to be worth anything — are
/// not themselves found by the scan below. `state.rs` and `git.rs` play the
/// same trick, for the same reason.
fn drop_needle() -> String {
    ["from_mode(0o", "000)"].concat()
}

/// The body of the `fn` enclosing byte offset `at`, plus `at` re-based into it.
///
/// The tree is rustfmt'd — `lint:fmt` is in the gate — so a function ends at the
/// first line that is exactly its own indent followed by `}`. That is exact for
/// formatted source and needs no brace matching, which a brace inside a string
/// or char literal would otherwise fool.
fn enclosing_fn(source: &str, at: usize) -> (&str, usize) {
    let mut start = 0;
    let mut indent = 0;
    let mut offset = 0;
    for line in source.lines() {
        if offset > at {
            break;
        }
        let trimmed = line.trim_start();
        let signature = trimmed
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub ")
            .trim_start_matches("async ");
        if signature.starts_with("fn ") {
            start = offset;
            indent = line.len() - trimmed.len();
        }
        offset += line.len() + 1;
    }
    let closing = format!("\n{}}}\n", " ".repeat(indent));
    let end = source[start..]
        .find(&closing)
        .map_or(source.len(), |rel| start + rel + closing.len());
    (&source[start..end], at - start)
}

/// The predicate, over one function body: between the drop at `drop_at` and the
/// read-back that decides whether the conclusion is reachable, there must be an
/// assertion that the drop landed.
///
/// Order is the whole discipline. Prove the setup took effect, *then* ask
/// whether it bites, and only then assert the conclusion — because a permission
/// drop is a premise the environment may refuse to create, and a conclusion
/// asserted over an uncreated premise is a green that certifies nothing.
fn premise_asserted(body: &str, drop_at: usize) -> Result<(), &'static str> {
    let after = &body[drop_at..];
    let read_back = ["read_to_string(", "File::open("]
        .iter()
        .filter_map(|token| after.find(token))
        .min()
        .ok_or(
            "no read-back after the permission drop — nothing establishes whether the bits bit, \
             so whatever follows is asserted over a precondition that may never have existed",
        )?;
    if ["assert!(", "assert_eq!(", "assert_ne!("]
        .iter()
        .filter_map(|token| after.find(token))
        .any(|assertion| assertion < read_back)
    {
        return Ok(());
    }
    Err(
        "no premise assertion between the permission drop and the read-back — assert that the \
         drop landed before asking whether it bites, or the setup can evaporate silently",
    )
}

/// 1-based line number of `at`, for a pointer-only failure message.
fn line_of(source: &str, at: usize) -> usize {
    source[..at].lines().count().max(1)
}

/// Every `*.rs` under `dir`, recursively, in a stable order — a gate's failure
/// message must not depend on `read_dir`'s filesystem-defined ordering.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(next) = stack.pop() {
        for entry in fs::read_dir(&next).expect("read a source directory") {
            let path = entry.expect("read dir entry").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

/// The audit's own fixtures: one well-formed shape and the two failing ones that
/// really shipped. `__DROP__` stands in for the needle so these are invisible to
/// the scan over the real tree.
const ASSERTS_ITS_PREMISE: &str = r#"    fn t() {
        fs::set_permissions(&p, fs::Permissions::__DROP__).expect("drop");
        assert_eq!(mode(&p), 0, "the drop landed");
        if fs::read_to_string(&p).is_ok() {
            return;
        }
        find(&d).expect_err("an unreadable file is not clean");
    }
"#;
const NO_READ_BACK: &str = r#"    fn t() {
        fs::set_permissions(&p, fs::Permissions::__DROP__).expect("drop");
        find(&d).expect_err("an unreadable file is not clean");
    }
"#;
const NO_PREMISE: &str = r#"    fn t() {
        fs::set_permissions(&p, fs::Permissions::__DROP__).expect("drop");
        if fs::read_to_string(&p).is_ok() {
            return;
        }
        find(&d).expect_err("an unreadable file is not clean");
    }
"#;

#[test]
fn every_permission_drop_asserts_its_own_premise() {
    // CLOUD-249. This environment runs as root, and root ignores the permission
    // bits: a `set_permissions(0o000)` followed by `expect_err` passed here
    // without ever entering the branch under test, so a green suite certified a
    // fix it never exercised. The obvious mitigation — an early return when the
    // setup did not take — only converts a silent pass into a silent skip.
    //
    // `from_mode(0o755)` sites are deliberately out of scope. They *grant*
    // rather than deny, and a grant that fails to bite fails its own test
    // loudly: the stub simply does not run.
    let needle = drop_needle();

    // (a) The audit is exercised before it is trusted — a check that cannot fail
    // certifies nothing, which is this test's own subject.
    for (label, fixture, holds) in [
        ("asserts its premise", ASSERTS_ITS_PREMISE, true),
        ("conclusion asserted with no read-back", NO_READ_BACK, false),
        ("read-back with no premise assertion", NO_PREMISE, false),
    ] {
        let source = fixture.replace("__DROP__", &needle);
        let at = source.find(&needle).expect("the fixture carries a drop");
        let (body, drop_at) = enclosing_fn(&source, at);
        let verdict = premise_asserted(body, drop_at);
        assert_eq!(
            verdict.is_ok(),
            holds,
            "the audit's own {label} fixture is judged wrong: {verdict:?}"
        );
    }

    // (b) The real sites.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut files = 0;
    let mut sites = 0;
    for dir in ["src", "tests"] {
        for path in rust_sources(&crate_dir.join(dir)) {
            let source = fs::read_to_string(&path).expect("read source");
            files += 1;
            let mut from = 0;
            while let Some(rel) = source[from..].find(&needle) {
                let at = from + rel;
                sites += 1;
                let (body, drop_at) = enclosing_fn(&source, at);
                let verdict = premise_asserted(body, drop_at);
                assert!(
                    verdict.is_ok(),
                    "{}:{}: {} (CLOUD-249)",
                    path.display(),
                    line_of(&source, at),
                    verdict.unwrap_err()
                );
                from = at + needle.len();
            }
        }
    }
    assert!(files > 0, "the audit must actually have read the crate");
    assert!(
        sites > 0,
        "the audit found no permission drop to judge — if the last one went away, remove the \
         audit with it rather than leaving behind a check that cannot fail"
    );
}

/// The needle, assembled rather than written, so this audit is invisible to
/// itself — the same reason [`drop_needle`] is built from halves.
fn xdg_needle() -> String {
    ["XDG_DATA", "_HOME"].concat()
}

#[test]
fn no_suite_sets_the_state_dir_variables_itself() {
    // CLOUD-619. `state::root` resolves through `etcetera`'s base strategy — XDG
    // on Linux and macOS, the roaming known folder on Windows — so a case that
    // isolates the store by exporting the XDG variable alone isolates NOTHING
    // there: the child reads the developer's real profile, sees another case's
    // leftovers, writes where nothing cleans up, and asserts about a store it
    // never controlled. One test noticed; the isolation had failed everywhere.
    //
    // THE FIX IS ONE AUTHORITY, NOT N CORRECT COPIES. An earlier version of this
    // audit allowed a site to keep its own `.env` calls so long as it mirrored
    // the Windows variable at the same value. That holds the property but keeps
    // fourteen copies of it, which is the shape CLOUD-63 built `common/` to end
    // and the shape that drifted here in the first place. So the rule is the one
    // the issue specifies: no suite names the variable at all — they call
    // `StateHome::state_home`, or `state_dir` when their root is not `<home>/data`.
    //
    // A TOKEN, NOT A CALL, is what this scans for, and the direction is what
    // makes that sound: it cannot mistake a correct site for a violation, only
    // fail to notice a suite that isolates nothing at all. That second case is
    // exactly what the `windows` job is a required check for.
    let needle = xdg_needle();
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut offenders = Vec::new();
    for path in rust_sources(&crate_dir.join("tests")) {
        // `common/` is where the one authority lives, so it is the one place the
        // variable is named — the carve-out IS the rule.
        if path.ends_with("common/mod.rs") {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read source");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            // Prose may name the variable — several module headers explain the
            // very rule this enforces. Only a site that SETS it is a violation,
            // and a doc comment sets nothing.
            let line_start = source[..at].rfind('\n').map_or(0, |nl| nl + 1);
            let line = &source[line_start..at];
            if line.trim_start().starts_with("//") {
                continue;
            }
            offenders.push(format!("{}:{}", path.display(), line_of(&source, at)));
        }
    }
    assert!(
        offenders.is_empty(),
        "a suite sets the state-dir variable itself. On Windows that redirects nothing — \
         `etcetera` reads the roaming known folder there — so the child writes to the real user \
         profile and every assertion about the store is about someone else's. Call \
         `state_home(<home>)`, or `state_dir(<dir>)` when the root is not `<home>/data` \
         (CLOUD-619):\n  {}",
        offenders.join("\n  ")
    );
}

/// The needle, assembled so this audit is invisible to itself.
fn path_env_needle() -> String {
    [".env(\"PA", "TH\""].concat()
}

/// The audit's own fixtures. `__PATH__` stands in for the needle.
const JOINS_PORTABLY: &str = r#"    fn t() {
        let path = std::env::join_paths(entries).expect("join");
        cmd.__PATH__, path);
    }
"#;
const INTERPOLATES_A_SEPARATOR: &str = r#"    fn t() {
        let path = format!("{bin}:{inherited}");
        cmd.__PATH__, path);
    }
"#;
const SETS_ONE_ENTRY: &str = r"    fn t() {
        cmd.__PATH__, bin.display().to_string());
    }
";

/// Whether the `PATH` override at `at` builds its value portably.
///
/// A function that composes a `PATH` at all must do it with `join_paths`; one
/// that sets a single entry composes nothing and is left alone.
fn path_joined_portably(body: &str) -> Result<(), &'static str> {
    // COMMENTS STRIPPED FIRST, because a mention is not a use — and this audit
    // caught itself on exactly that: the comment written beside the fix names
    // `join_paths`, so the reverted defect underneath it still read as though it
    // held, and the gate passed over a real regression. The same distinction
    // `closing-key-check` draws for its own hold marker. Line-initial `//` is
    // exact for a rustfmt'd tree, which `lint:fmt` guarantees.
    let code: String = body
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    if code.contains("join_paths") || !code.contains("format!") {
        return Ok(());
    }
    Err(
        "this `PATH` is composed with `format!` rather than `std::env::join_paths` — the \
         separator is `;` on Windows and a path there begins `D:\\`, so an interpolated `:` does \
         not merely fail to separate, it yields a PATH whose first entry is a drive letter and \
         whose second swallows everything after it",
    )
}

#[test]
fn every_path_override_is_composed_with_join_paths() {
    // CLOUD-617/CLOUD-113. `judge_kind` built `format!("{bin}:{inherited}")`, so
    // on Windows the fixture's stub was not on PATH at all and seven of fourteen
    // cases reported `cannot run judge program` in place of the verdict
    // discipline they exist to assert. The misattribution is the expensive part:
    // it read as a defect in the engine's PATH lookup, which was correct
    // throughout — `lookup_on` has always used `split_paths`.
    //
    // Sited here rather than as a lint because the property is about the test
    // tree's own fixtures: production code resolves PATH through `split_paths`
    // and never composes one.
    let needle = path_env_needle();

    // (a) Exercise the audit first, including the case that must NOT fire: a
    // single-entry PATH composes nothing and needs no join.
    for (label, fixture, holds) in [
        ("joins portably", JOINS_PORTABLY, true),
        ("interpolates a separator", INTERPOLATES_A_SEPARATOR, false),
        ("sets one entry", SETS_ONE_ENTRY, true),
    ] {
        let source = fixture.replace("__PATH__", &needle);
        let at = source.find(&needle).expect("the fixture sets PATH");
        let (body, _) = enclosing_fn(&source, at);
        let verdict = path_joined_portably(body);
        assert_eq!(
            verdict.is_ok(),
            holds,
            "the audit's own {label} fixture is judged wrong: {verdict:?}"
        );
    }

    // (b) The real sites.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut sites = 0;
    for path in rust_sources(&crate_dir.join("tests")) {
        let source = fs::read_to_string(&path).expect("read source");
        let mut from = 0;
        while let Some(rel) = source[from..].find(&needle) {
            let at = from + rel;
            from = at + needle.len();
            sites += 1;
            let (body, _) = enclosing_fn(&source, at);
            if let Err(why) = path_joined_portably(body) {
                panic!(
                    "{}:{}: {why} (CLOUD-617)",
                    path.display(),
                    line_of(&source, at)
                );
            }
        }
    }
    assert!(
        sites > 0,
        "the audit found no PATH override to judge — if the last one went away, remove the audit \
         with it rather than leaving behind a check that cannot fail"
    );
}

/// The path-valued TOML keys a fixture writes. Each names a filesystem location
/// or a `file://` URL over one, which is what makes the string form decide
/// whether the config parses at all on Windows.
const PATH_VALUED_KEYS: [&str; 5] = ["url", "path", "check", "binary", "script"];

/// The offending shape, assembled so this audit is invisible to itself.
fn basic_string_interpolation(key: &str) -> String {
    [key, " = \\\"{"].concat()
}

#[test]
fn every_path_valued_toml_key_uses_a_literal_string() {
    // CLOUD-113, found three separate times on three separate Windows runs, each
    // costing a round trip and each looking like a defect in the subject rather
    // than in the fixture:
    //
    //   doctor           `check = "…"`  -> the rule's own script path
    //   enforce_journal  `url = "…"`    -> `file://` over the artifacts dir
    //   secrets_kind     `url = "…"`    -> the same
    //   provision        `url = "…"`    -> the same, nine of ten cases
    //
    // A TOML *basic* string processes escapes. A Windows path interpolated into
    // one reads `\a` as a control character and rejects `\U` outright, so the
    // config never parses and every case in the suite reports a config error in
    // place of the behaviour it asserts. A *literal* string processes nothing.
    //
    // KEYED ON THE KEY, NOT ON THE VALUE, and that is the whole point. Twice I
    // scanned this class by asking "can this value be a path?", and twice the
    // answer was wrong — `provision.rs` was read as safe one run before it
    // failed nine cases. Whether a value is a path is a judgement; which key it
    // sits under is a fact. Keys whose values are never paths are left alone
    // rather than swept in, so the rule stays about the thing that bites.
    let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // Collected rather than panicked on at the first hit: this class arrives in
    // batches — nine cases in one suite, four in another — and a gate that names
    // one offender per run turns one fix into one CI round trip each.
    let mut offenders = Vec::new();
    for path in rust_sources(&crate_dir.join("tests")) {
        let source = fs::read_to_string(&path).expect("read source");
        for key in PATH_VALUED_KEYS {
            let needle = basic_string_interpolation(key);
            let mut from = 0;
            while let Some(rel) = source[from..].find(&needle) {
                let at = from + rel;
                from = at + needle.len();
                offenders.push(format!(
                    "{}:{}: `{key}` interpolated into a basic string; write `{key} = '{{…}}'`",
                    path.display(),
                    line_of(&source, at)
                ));
            }
        }
    }
    // Zero is the passing state, so unlike the audits above there is no
    // population floor to assert. What keeps it honest is the negative run:
    // reverting any of the four sites it was written for makes it fire.
    assert!(
        offenders.is_empty(),
        "a path-valued TOML key is interpolated into a BASIC string, where a Windows path reads \
         `\\a` as a control character and `\\U` is rejected outright — the config then fails to \
         parse and every case dies on its own fixture rather than on its subject. A literal \
         string processes no escapes (CLOUD-113):\n  {}",
        offenders.join("\n  ")
    );
}
