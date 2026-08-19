//! End-to-end tests for `batten commit` over the compiled binary (CLOUD-701).
//!
//! Every case drives a **throwaway repository** with its own `batten.toml`. The
//! property under test is "a subject that does not match the configured pattern
//! is refused", and the pattern is consumer data — so a fixture that judged this
//! repository's history would be testing this repository's convention rather than
//! the mechanism that enforces whatever convention a consumer declares.
//!
//! The fixture pattern is deliberately NOT this repo's: a narrow three-type one,
//! so a case fails when the engine stops reading the config rather than when it
//! happens to agree with the committed default.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};
use std::process::Output;

use common::{batten, git_in, scratch, stderr, stdout, write};

/// A convention narrower than this repository's, so the cases prove the engine
/// reads the config rather than agreeing with it by coincidence.
const POLICY: &str = r"version = 1

[commit]
subject_pattern = '^(feat|fix|chore)([(][a-z]+[)])?!?: .+'
";

/// A fixture repository with `POLICY` committed and one base commit.
fn fixture(name: &str) -> PathBuf {
    fixture_with(name, POLICY)
}

fn fixture_with(name: &str, config: &str) -> PathBuf {
    let dir = scratch(name);
    git_in(&dir, &["init", "-q", "-b", "main"]);
    git_in(&dir, &["config", "user.name", "Accountable Human"]);
    git_in(&dir, &["config", "user.email", "human@example.test"]);
    write(&dir, "batten.toml", config);
    git_in(&dir, &["add", "batten.toml"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: base"]);
    dir
}

fn commit(dir: &Path, subject: &str) -> String {
    git_in(dir, &["commit", "-q", "--allow-empty", "-m", subject]);
    git_in(dir, &["rev-parse", "HEAD"])
}

fn check_range(dir: &Path, base: &str, head: &str) -> Output {
    batten()
        .args(["commit", "check", &format!("{base}..{head}")])
        .current_dir(dir)
        .output()
        .expect("run batten")
}

fn check_message(dir: &Path, body: &str) -> Output {
    write(dir, "msg", body);
    batten()
        .args(["commit", "check", "--message", "msg"])
        .current_dir(dir)
        .output()
        .expect("run batten")
}

fn short(sha: &str) -> String {
    sha.chars().take(8).collect()
}

fn head(dir: &Path) -> String {
    git_in(dir, &["rev-parse", "HEAD"])
}

// --- the clean path -----------------------------------------------------------

#[test]
fn a_conventional_range_is_silent_and_exits_zero() {
    let dir = fixture("commit-clean");
    let base = head(&dir);
    let last = commit(&dir, "feat(cli): a real change");
    let out = check_range(&dir, &base, &last);
    assert_eq!(out.status.code(), Some(0));
    // Silence is the success signal on the human channel (§6). Asserted as an
    // exact empty string: a gate that prints reassurance is one whose real
    // findings scroll away.
    assert_eq!(stdout(&out), "");
}

#[test]
fn an_empty_range_is_clean_rather_than_an_error() {
    let dir = fixture("commit-empty-range");
    let base = head(&dir);
    let out = check_range(&dir, &base, &base);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn every_declared_type_and_the_optional_scope_and_bang_are_accepted() {
    // The pattern is data, so this asserts the engine applies it faithfully
    // rather than that this particular vocabulary is right.
    let dir = fixture("commit-vocabulary");
    let base = head(&dir);
    for subject in ["feat: a", "fix(cli): b", "chore!: c", "fix(cli)!: d"] {
        commit(&dir, subject);
    }
    let out = check_range(&dir, &base, &head(&dir));
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

// --- refusals ------------------------------------------------------------------

#[test]
fn a_non_conventional_subject_is_refused_and_the_pointer_names_the_field() {
    let dir = fixture("commit-bad-subject");
    let base = head(&dir);
    let last = commit(&dir, "just did some stuff");
    let out = check_range(&dir, &base, &last);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), format!("{} subject\n", short(&last)));
}

#[test]
fn the_subject_text_is_never_echoed() {
    // The deliberate tightening over the shell task this replaces, which printed
    // the offending subject. A subject carries whatever its author typed, so a
    // gate that echoes it back republishes arbitrary content (§6, rule 4).
    let dir = fixture("commit-no-echo");
    let base = head(&dir);
    let last = commit(&dir, "wip UNIQUEMARKER left in");
    let out = check_range(&dir, &base, &last);
    assert_eq!(out.status.code(), Some(2));
    assert!(!stdout(&out).contains("UNIQUEMARKER"));
    assert!(!stderr(&out).contains("UNIQUEMARKER"));
}

#[test]
fn a_type_outside_the_configured_vocabulary_is_refused() {
    // `docs:` is conventional in general and NOT in this fixture's config, which
    // is what proves the verdict comes from the config rather than from a notion
    // of Conventional Commits compiled into the engine.
    let dir = fixture("commit-foreign-type");
    let base = head(&dir);
    let last = commit(&dir, "docs: a real change");
    let out = check_range(&dir, &base, &last);
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), format!("{} subject\n", short(&last)));
}

#[test]
fn every_offending_commit_is_reported_not_just_the_first() {
    let dir = fixture("commit-all-reported");
    let base = head(&dir);
    let first = commit(&dir, "nope one");
    commit(&dir, "feat: fine");
    let third = commit(&dir, "nope two");
    let out = check_range(&dir, &base, &head(&dir));
    assert_eq!(out.status.code(), Some(2));
    // `git log` is newest-first, so the later commit leads.
    assert_eq!(
        stdout(&out),
        format!("{} subject\n{} subject\n", short(&third), short(&first))
    );
}

#[test]
fn a_merge_commit_is_not_judged() {
    // `--no-merges`: a merge subject is git's own wording, not an author's, and
    // holding it to the convention would refuse work nobody wrote.
    let dir = fixture("commit-merge");
    let base = head(&dir);
    git_in(&dir, &["checkout", "-q", "-b", "side"]);
    commit(&dir, "feat: on the side");
    git_in(&dir, &["checkout", "-q", "main"]);
    commit(&dir, "feat: on main");
    git_in(
        &dir,
        &[
            "merge",
            "-q",
            "--no-ff",
            "-m",
            "Merge branch 'side'",
            "side",
        ],
    );
    let out = check_range(&dir, &base, &head(&dir));
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
}

// --- message mode: the commit-time seam ---------------------------------------

#[test]
fn message_mode_refuses_a_pending_subject_before_the_commit_exists() {
    let dir = fixture("commit-message-bad");
    let out = check_message(&dir, "just did some stuff\n\nRefs: CLOUD-701\n");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "pending subject\n");
}

#[test]
fn message_mode_passes_a_conventional_pending_subject() {
    let dir = fixture("commit-message-good");
    let out = check_message(&dir, "feat(cli): a real change\n\nRefs: CLOUD-701\n");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), "");
}

#[test]
fn message_mode_judges_the_first_line_only() {
    // The body is not the subject: a conventional first line stands even when
    // later lines would not match, which is what `%s` means once the commit
    // exists and is the property the two modes must agree on.
    let dir = fixture("commit-message-body");
    let out = check_message(
        &dir,
        "feat: a real change\n\nnot a conventional line at all\n",
    );
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn an_empty_message_is_refused_rather_than_waved_through() {
    let dir = fixture("commit-message-empty");
    let out = check_message(&dir, "");
    assert_eq!(out.status.code(), Some(2));
    assert_eq!(stdout(&out), "pending subject\n");
}

// --- could-not-look is 1, never a pass ----------------------------------------

#[test]
fn an_unresolvable_range_is_one_not_a_pass() {
    let dir = fixture("commit-bad-range");
    let base = head(&dir);
    let out = check_range(&dir, &base, "0000000000000000000000000000000000000000");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn a_malformed_range_is_one() {
    let dir = fixture("commit-malformed-range");
    let out = batten()
        .args(["commit", "check", "not-a-range"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn neither_mode_is_one_rather_than_a_vacuous_pass() {
    // A gate invoked with nothing to judge must not exit 0, which would read
    // identically to "these subjects are conventional".
    let dir = fixture("commit-no-mode");
    let out = batten()
        .args(["commit", "check"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn both_modes_at_once_is_one() {
    let dir = fixture("commit-both-modes");
    write(&dir, "msg", "feat: a change\n");
    let out = batten()
        .args(["commit", "check", "HEAD..HEAD", "--message", "msg"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn an_unreadable_message_file_is_one() {
    let dir = fixture("commit-message-missing");
    let out = batten()
        .args(["commit", "check", "--message", "does-not-exist"])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(1));
}

#[test]
fn no_commit_table_is_one_not_a_silent_pass() {
    // "This repository declares no convention" and "these subjects are
    // conventional" are different answers; collapsing them reports green over a
    // gate that never ran.
    let dir = fixture_with("commit-no-table", "version = 1\n");
    let base = head(&dir);
    let last = commit(&dir, "anything at all");
    assert_eq!(check_range(&dir, &base, &last).status.code(), Some(1));
}

#[test]
fn an_uncompilable_pattern_is_refused_at_load_and_names_the_key() {
    let dir = fixture_with(
        "commit-bad-pattern",
        "version = 1\n\n[commit]\nsubject_pattern = '(unclosed'\n",
    );
    let base = head(&dir);
    let last = commit(&dir, "feat: a change");
    let out = check_range(&dir, &base, &last);
    assert_eq!(out.status.code(), Some(1));
    // The pattern is the consumer's own config, so naming it is a pointer to the
    // line they must fix — not a payload leak.
    assert!(stderr(&out).contains("subject_pattern"));
}

#[test]
fn an_empty_pattern_is_refused_at_load() {
    let dir = fixture_with(
        "commit-empty-pattern",
        "version = 1\n\n[commit]\nsubject_pattern = ''\n",
    );
    let base = head(&dir);
    let last = commit(&dir, "feat: a change");
    assert_eq!(check_range(&dir, &base, &last).status.code(), Some(1));
}

// --- JSON is emitted unconditionally, including when clean ---------------------

#[test]
fn json_is_emitted_for_a_clean_run_too() {
    // JSON that is sometimes absent is unparseable, so the empty array is the
    // clean answer rather than silence.
    let dir = fixture("commit-json-clean");
    let base = head(&dir);
    let last = commit(&dir, "feat: a change");
    let out = batten()
        .args(["commit", "check", "--json", &format!("{base}..{last}")])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out).trim(), "[]");
}

#[test]
fn json_carries_the_pointer_and_no_payload() {
    let dir = fixture("commit-json-finding");
    let base = head(&dir);
    let last = commit(&dir, "wip UNIQUEMARKER stuff");
    let out = batten()
        .args(["commit", "check", "--json", &format!("{base}..{last}")])
        .current_dir(&dir)
        .output()
        .expect("run batten");
    assert_eq!(out.status.code(), Some(2));
    let rendered = stdout(&out);
    assert!(rendered.contains("subject"));
    assert!(rendered.contains(&short(&last)));
    assert!(!rendered.contains("UNIQUEMARKER"));
}
