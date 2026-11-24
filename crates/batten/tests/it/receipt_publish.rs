//! Published receipts (CLOUD-1544): publish from one clone to a state
//! repository, pull into a second, and the second answers `Valid`.
//!
//! # The remote is a real bare repository, behind the transport's one door
//!
//! `land::receipts` speaks smart-HTTP through `lease`, and every exchange goes
//! through `fetch::spend`. The stand-in below answers those exchanges by running
//! `git upload-pack` and `git receive-pack --stateless-rpc` over a local bare
//! repository — what `git http-backend` does — so the ref, the commit and the
//! compare-and-swap are git's own, and no case reaches the network. The verdicts
//! are read off the COMPILED binary's `receipt status`, so the reader under test
//! is the one a gate runs.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};

use crate::common::{Fixture, StateHome as _, batten, git_in, scratch, stdout};
use batten::land::receipts;

/// Any URL: the stand-in answers every call, so the host is never resolved.
const REMOTE: &str = "https://state.invalid/owner/state";

/// Run git in `dir` with `input` on stdin, returning stdout.
#[expect(
    clippy::disallowed_types,
    reason = "test-only: the stand-in IS git's own server half over a local bare repository, which is what makes the CAS under test git's rather than a mock's"
)]
fn git_with(dir: &Path, args: &[&str], input: &[u8]) -> Vec<u8> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let mut child = Command::new("git")
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start git");
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output.stdout
}

/// One pkt-line.
fn pkt(line: &str) -> Vec<u8> {
    format!("{:04x}{line}", line.len() + 4).into_bytes()
}

/// Answer one smart-HTTP call from the bare repository at `bare`.
fn serve(bare: &Path, call: &batten::fetch::Call<'_>) -> batten::fetch::Response {
    let body = if let Some((_, service)) = call.url.split_once("/info/refs?service=") {
        let verb = service.trim_start_matches("git-");
        let mut body = pkt(&format!("# service={service}\n"));
        body.extend_from_slice(b"0000");
        body.extend(git_with(
            bare,
            &[verb, "--stateless-rpc", "--advertise-refs", "."],
            b"",
        ));
        body
    } else {
        let service = call.url.rsplit('/').next().unwrap();
        let verb = service.trim_start_matches("git-");
        git_with(
            bare,
            &[verb, "--stateless-rpc", "."],
            call.body.unwrap_or_default(),
        )
    };
    batten::fetch::Response {
        status: 200,
        body,
        headers: Vec::new(),
    }
}

/// Stand the bare repository at `bare` up as this thread's remote, calling
/// `before` with each call first.
fn stand_up(bare: PathBuf, before: impl Fn(&batten::fetch::Call<'_>) + 'static) {
    batten::fetch::stand_in(Box::new(move |calls| {
        Ok(calls
            .iter()
            .map(|call| {
                before(call);
                serve(&bare, call)
            })
            .collect())
    }));
}

/// An empty bare repository standing in for the state repository.
fn state_repo(case: &str) -> PathBuf {
    let bare = scratch(&format!("{case}-state-git")).join("state.git");
    std::fs::create_dir_all(&bare).unwrap();
    git_in(&bare, &["init", "--bare", "-q"]);
    bare
}

/// The first clone: a committed config, one commit, `origin/main` at it.
fn first_clone(case: &str) -> PathBuf {
    let dir = Fixture::at(scratch(&format!("{case}-one")).join("one"))
        .config("version = 1\n\n[receipt]\nverified_by = [\"verify\"]\n")
        .file("src.rs", "fn main() {}\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    dir
}

/// A second clone of `first` at the same HEAD, with its own `origin/main`.
fn second_clone(case: &str, first: &Path) -> PathBuf {
    let dir = scratch(&format!("{case}-two")).join("two");
    git_in(
        first,
        &[
            "clone",
            "-q",
            first.to_str().unwrap(),
            dir.to_str().unwrap(),
        ],
    );
    dir
}

/// This clone's canonical receipt store under `state`.
fn receipts_dir(state: &Path, repo: &Path) -> PathBuf {
    state
        .join(batten::state::derive_repo_name(repo).unwrap())
        .join("receipts")
}

fn record(repo: &Path, state: &Path, check: &str) {
    let output = batten()
        .args(["receipt", "record", check])
        .current_dir(repo)
        .state_dir(state)
        .streamed_output()
        .expect("run batten receipt record");
    assert!(output.status.success(), "record {check}: {output:?}");
}

/// `receipt status <check>`'s exit and line, from the compiled binary.
fn status(repo: &Path, state: &Path, check: &str) -> (Option<i32>, String) {
    let output = batten()
        .args(["receipt", "status", check])
        .current_dir(repo)
        .state_dir(state)
        .streamed_output()
        .expect("run batten receipt status");
    (output.status.code(), stdout(&output))
}

/// Publish `repo`'s local set to `name`.
fn publish(repo: &Path, state: &Path, name: &str, seconds: i64) -> receipts::Moved {
    let local = receipts::local_set(
        &receipts_dir(state, repo),
        &repo.join(".git").join("batten-receipts"),
    );
    receipts::publish(REMOTE, &repo.join(".git"), name, &local, seconds).expect("publish")
}

/// Pull `name` into `repo`.
fn pull(repo: &Path, state: &Path, name: &str) -> receipts::Moved {
    let head = git_in(repo, &["rev-parse", "HEAD"]).trim().to_owned();
    receipts::pull(
        REMOTE,
        &repo.join(".git"),
        name,
        &receipts_dir(state, repo),
        &repo.join(".git").join("batten-receipts"),
        &head,
    )
    .expect("pull")
}

/// Fails by: the published class keeping the git-dir conjunct
/// (`published-receipt-gitdir-required`), so a receipt pulled into a second
/// clone still reads `missing`.
#[test]
fn a_published_receipt_pulled_into_a_second_clone_is_valid() {
    let case = "receipt-publish-second-clone";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let one = first_clone(case);
    let two = second_clone(case, &one);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );
    let name = receipts::reference("work").unwrap();

    record(&one, &state_one, "verify");
    assert_eq!(status(&one, &state_one, "verify").0, Some(0));
    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(2), "nothing pulled yet: {line}");
    assert!(line.ends_with(" missing\n"), "{line}");

    let published = publish(&one, &state_one, &name, 1_700_000_000);
    assert!(
        published.count >= 2,
        "the statement and its compat file: {published:?}"
    );
    let pulled = pull(&two, &state_two, &name);
    assert_eq!(pulled.commit, published.commit);
    assert!(pulled.count >= 1, "{pulled:?}");

    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(0), "the pulled receipt answers: {line}");
    assert!(line.ends_with(" valid\n"), "{line}");
    // The verb that reads the compatibility layout agrees, from the same pull.
    let verified = batten()
        .args(["receipt", "verified"])
        .current_dir(&two)
        .state_dir(&state_two)
        .streamed_output()
        .unwrap();
    assert!(verified.status.success(), "{verified:?}");
}

/// Fails by: a publish setting the observed head as the new commit's parent
/// (`publish-chains-parent`), so the ref grows a history.
#[test]
fn every_publish_mints_a_parentless_commit() {
    let case = "receipt-publish-parentless";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let one = first_clone(case);
    let state = scratch(&format!("{case}-state")).join("state");
    let name = receipts::reference("work").unwrap();

    record(&one, &state, "verify");
    let first = publish(&one, &state, &name, 1_700_000_000);
    record(&one, &state, "linear-check");
    let second = publish(&one, &state, &name, 1_700_000_100);
    assert_ne!(first.commit, second.commit, "a new receipt moves the ref");

    for commit in [&first.commit, &second.commit] {
        let parents = git_in(&bare, &["rev-list", "--parents", "-n", "1", commit]);
        assert_eq!(
            parents.split_whitespace().count(),
            1,
            "{commit} has a parent: {parents}"
        );
    }
    assert_eq!(
        git_in(&bare, &["rev-parse", &name]).trim(),
        second.commit,
        "the ref reads the last publish"
    );
    let listed = git_in(&bare, &["ls-tree", "-r", "--name-only", &name]);
    let statements = listed
        .lines()
        .filter(|path| path.starts_with("statement/"))
        .count();
    assert_eq!(statements, 2, "the union kept both checks: {listed}");
}

/// The anti-vacuity control: a published receipt minted under another
/// governing surface answers `missing`, so the published arm is not "any
/// pulled file is valid".
#[test]
fn a_published_receipt_under_another_epoch_is_missing() {
    let case = "receipt-publish-other-epoch";
    let bare = state_repo(case);
    stand_up(bare.clone(), |_| {});
    let one = first_clone(case);
    let two = second_clone(case, &one);
    let (state_one, state_two) = (
        scratch(&format!("{case}-state-1")).join("state-1"),
        scratch(&format!("{case}-state-2")).join("state-2"),
    );
    let name = receipts::reference("work").unwrap();

    record(&one, &state_one, "verify");
    // The epoch a different governing surface would have bound.
    for entry in std::fs::read_dir(receipts_dir(&state_one, &one)).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|ext| ext == "json") {
            let mut statement: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            statement["predicate"]["configEpoch"] = "0".repeat(64).into();
            std::fs::write(&path, serde_json::to_vec_pretty(&statement).unwrap()).unwrap();
        }
    }
    publish(&one, &state_one, &name, 1_700_000_000);
    pull(&two, &state_two, &name);

    let (code, line) = status(&two, &state_two, "verify");
    assert_eq!(code, Some(2), "{line}");
    assert!(line.ends_with(" missing\n"), "{line}");
}

/// A rival publish landing between this publish's fetch and its swap: the swap
/// loses, the publish re-fetches, and the final tree is the union.
#[test]
fn a_lost_swap_retries_and_keeps_the_rivals_receipts() {
    let case = "receipt-publish-cas-loss";
    let bare = state_repo(case);
    let name = receipts::reference("work").unwrap();
    let rival = std::cell::Cell::new(false);
    let (bare_for_rival, name_for_rival) = (bare.clone(), name.clone());
    stand_up(bare.clone(), move |call| {
        if call.url.ends_with("/git-receive-pack") && !rival.replace(true) {
            // Another session's set, swapped in by git itself.
            let blob = git_with(
                &bare_for_rival,
                &["hash-object", "-w", "--stdin"],
                b"base x\n",
            );
            let blob = String::from_utf8(blob).unwrap();
            let kind = git_with(
                &bare_for_rival,
                &["mktree"],
                format!("100644 blob {}\tclaim.rival\n", blob.trim()).as_bytes(),
            );
            let kind = String::from_utf8(kind).unwrap();
            let root = git_with(
                &bare_for_rival,
                &["mktree"],
                format!("040000 tree {}\tcompat\n", kind.trim()).as_bytes(),
            );
            let root = String::from_utf8(root).unwrap();
            let commit = git_with(
                &bare_for_rival,
                &[
                    "-c",
                    "user.name=rival",
                    "-c",
                    "user.email=rival@localhost",
                    "commit-tree",
                    root.trim(),
                    "-m",
                    "rival",
                ],
                b"",
            );
            let commit = String::from_utf8(commit).unwrap();
            git_in(
                &bare_for_rival,
                &["update-ref", &name_for_rival, commit.trim()],
            );
        }
    });
    let one = first_clone(case);
    let state = scratch(&format!("{case}-state")).join("state");
    record(&one, &state, "verify");

    let published = publish(&one, &state, &name, 1_700_000_000);
    assert_eq!(
        git_in(&bare, &["rev-parse", &name]).trim(),
        published.commit
    );
    let listed = git_in(&bare, &["ls-tree", "-r", "--name-only", &name]);
    assert!(
        listed.contains("compat/claim.rival"),
        "the rival's receipt: {listed}"
    );
    assert!(
        listed.lines().any(|path| path.starts_with("statement/")),
        "this clone's receipt: {listed}"
    );
}

/// Fails by: an unset variable deriving, calling or writing anything.
#[test]
fn unset_is_off_and_writes_nothing() {
    let case = "receipt-publish-unset";
    let one = first_clone(case);
    let state = scratch(&format!("{case}-state")).join("state");
    for verb in ["publish", "pull"] {
        let output = batten()
            .args(["receipt", verb])
            .current_dir(&one)
            .state_dir(&state)
            .streamed_output()
            .unwrap();
        assert_eq!(output.status.code(), Some(0), "{verb}: {output:?}");
        assert_eq!(stdout(&output), "off\n", "{verb}");
    }
    assert!(!state.exists(), "off must leave no trace");
}

/// Fails by: a project with no `http(s)` origin being taken as a remote.
#[test]
fn a_local_path_origin_is_refused_never_a_verdict() {
    let case = "receipt-publish-local-origin";
    let one = first_clone(case);
    git_in(&one, &["remote", "add", "origin", "/srv/git/widgets.git"]);
    let output = batten()
        .args(["receipt", "publish"])
        .current_dir(&one)
        .env(batten::session::STATE_REPO_ENV, "owner/state")
        .state_dir(&scratch(&format!("{case}-state")).join("state"))
        .streamed_output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(stdout(&output), "no-http-origin\n");
}
