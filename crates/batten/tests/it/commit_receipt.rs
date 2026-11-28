//! `commit check` and `attribution check --range` keep a receipt per commit
//! (CLOUD-2962), so one new commit on a branch judges one.
//!
//! Every case reads the closing line on stderr, `judged <J> of <N>, <H> held`,
//! over a fixture repository built in the case: the line is the count of
//! commits the clauses actually ran over, so a receipt that never held, or one
//! that held when it must not, moves it.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{batten, git_in, scratch, stderr, write};

/// A subject convention, an attribution policy, and a protected glob only
/// when asked for: the policy edit a case makes in the working tree.
fn config(protected: bool) -> String {
    let protected = if protected {
        "protected = [\"guarded/**\"]\n"
    } else {
        ""
    };
    format!(
        "version = 1\n{protected}\n\
         [commit]\nsubject_pattern = \"^(feat|fix|chore)(\\\\(.+\\\\))?!?: .+\"\n\n\
         [attribution]\nidentity_deny = ['^Vendorbot <']\n\
         trailer_deny = ['^Vendorbot-Session:']\n\
         body_deny = ['[Gg]enerated with']\ntrailer_allow = []\n"
    )
}

/// A repository with the policy committed as its base, and the base's id.
fn fixture(name: &str) -> (PathBuf, String) {
    let dir = scratch(name);
    git_in(&dir, &["init", "-q", "-b", "main"]);
    git_in(&dir, &["config", "user.name", "Accountable Human"]);
    git_in(&dir, &["config", "user.email", "human@example.test"]);
    write(&dir, "batten.toml", &config(false));
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    let base = head(&dir);
    (dir, base)
}

fn head(dir: &Path) -> String {
    git_in(dir, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// Write `path` and commit it with `message`.
fn commit(dir: &Path, path: &str, body: &str, message: &str) {
    write(dir, path, body);
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", message]);
}

/// Three conventional commits, each writing its own file.
fn three(dir: &Path) {
    commit(dir, "a.txt", "a\n", "feat: one");
    commit(dir, "b.txt", "b\n", "feat: two");
    commit(dir, "c.txt", "c\n", "feat: three");
}

/// `batten <verb> check <base>..HEAD`, as (exit code, stderr).
fn check(dir: &Path, verb: &str, base: &str) -> (Option<i32>, String) {
    let output = batten()
        .current_dir(dir)
        .args([verb, "check", &format!("{base}..HEAD")])
        .output()
        .expect("run batten");
    (output.status.code(), stderr(&output))
}

fn commit_check(dir: &Path, base: &str) -> (Option<i32>, String) {
    check(dir, "commit", base)
}

#[test]
fn one_new_commit_judges_one() {
    let (dir, base) = fixture("receipt-one-new");
    three(&dir);
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("commit check: judged 3 of 3, 0 held"),
        "{said}"
    );
    commit(&dir, "d.txt", "d\n", "feat: four");
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("commit check: judged 1 of 4, 3 held"),
        "{said}"
    );
}

#[test]
fn a_rebase_that_changes_no_commit_judges_none() {
    let (dir, base) = fixture("receipt-rebase");
    three(&dir);
    let (_, said) = commit_check(&dir, &base);
    assert!(said.contains("judged 3 of 3, 0 held"), "{said}");
    let before = head(&dir);
    // Another base under the same three commits: new ids, same changes.
    git_in(&dir, &["checkout", "-q", "-b", "other", &base]);
    commit(&dir, "elsewhere.txt", "e\n", "chore: another base");
    let other = head(&dir);
    git_in(&dir, &["cherry-pick", &format!("{base}..main")]);
    assert_ne!(head(&dir), before, "the replay must mint new ids");
    let (code, said) = commit_check(&dir, &other);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("commit check: judged 0 of 3, 3 held"),
        "{said}"
    );
}

#[test]
fn an_amended_author_is_judged_again() {
    let (dir, base) = fixture("receipt-author");
    three(&dir);
    let (_, said) = commit_check(&dir, &base);
    assert!(said.contains("judged 3 of 3, 0 held"), "{said}");
    git_in(
        &dir,
        &[
            "commit",
            "-q",
            "--amend",
            "--no-edit",
            "--author",
            "Another Human <another@example.test>",
        ],
    );
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("commit check: judged 1 of 3, 2 held"),
        "{said}"
    );
}

#[test]
fn a_failing_commit_is_judged_every_time() {
    let (dir, base) = fixture("receipt-failing");
    commit(&dir, "a.txt", "a\n", "feat: one");
    commit(&dir, "b.txt", "b\n", "not a conventional subject");
    commit(&dir, "c.txt", "c\n", "feat: three");
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(code, Some(2), "{said}");
    assert!(
        said.contains("commit check: judged 3 of 3, 0 held"),
        "{said}"
    );
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(
        code,
        Some(2),
        "the finding stands on the second run: {said}"
    );
    assert!(
        said.contains("commit check: judged 1 of 3, 2 held"),
        "{said}"
    );
}

#[test]
fn a_policy_edit_judges_every_commit() {
    let (dir, base) = fixture("receipt-policy");
    three(&dir);
    let (_, said) = commit_check(&dir, &base);
    assert!(said.contains("judged 3 of 3, 0 held"), "{said}");
    // Uncommitted: the verdict runs under the working tree's policy.
    write(&dir, "batten.toml", &config(true));
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("commit check: judged 3 of 3, 0 held"),
        "{said}"
    );
}

#[test]
fn a_ledger_content_change_under_the_same_paths_is_judged_again() {
    let (dir, base) = fixture("receipt-ledger");
    commit(&dir, "a.txt", "a\n", "feat: one");
    commit(&dir, "b.txt", "b\n", "feat: two");
    commit(&dir, "successors/alpha.rs", "// one row\n", "feat: three");
    let (_, said) = commit_check(&dir, &base);
    assert!(said.contains("judged 3 of 3, 0 held"), "{said}");
    // Same message, same path, other content.
    write(&dir, "successors/alpha.rs", "// another row\n");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "--amend", "--no-edit"]);
    let (code, said) = commit_check(&dir, &base);
    assert_eq!(code, Some(0), "{said}");
    assert!(
        said.contains("commit check: judged 1 of 3, 2 held"),
        "{said}"
    );
}

#[test]
fn attribution_judges_one_new_commit() {
    let (dir, base) = fixture("receipt-attribution");
    three(&dir);
    let output = batten()
        .current_dir(&dir)
        .args(["attribution", "check", &format!("{base}..HEAD")])
        .output()
        .expect("run batten");
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert!(
        said.contains("attribution check: judged 3 of 3, 0 held"),
        "{said}"
    );
    commit(&dir, "d.txt", "d\n", "feat: four");
    let output = batten()
        .current_dir(&dir)
        .args(["attribution", "check", &format!("{base}..HEAD")])
        .output()
        .expect("run batten");
    let said = stderr(&output);
    assert_eq!(output.status.code(), Some(0), "{said}");
    assert!(
        said.contains("attribution check: judged 1 of 4, 3 held"),
        "{said}"
    );
}
