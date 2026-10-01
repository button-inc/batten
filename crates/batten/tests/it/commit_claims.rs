//! Every commit in a judged range names the row it serves, over the compiled
//! binary (CLOUD-431's server-side half; retired off `commit-lint`'s shell body by
//! CLOUD-843).
//!
//! # What only this tier can decide
//!
//! `commit.rs`'s unit cases pin the PREDICATE over evidence they build by hand.
//! What they cannot see is whether `commit check <base>..<head>` GATHERS it: that
//! the range is walked with merges excluded, that each message is read through
//! the consumer's `[[pattern]]` grammar the way `claim keys` reads it, and that a
//! commit's paths and AUTHOR address come off git rather than off its committer.
//! The retired body got each of those from a spawn per commit; the engine gets
//! them in process, and a wrong one here is a claim clause deciding over nothing.
//!
//! # The retired body, clause by clause
//!
//! * `for sha in $(git rev-list --no-merges BASE..HEAD)` — the range walk:
//!   `every_commit_in_the_range_is_judged_and_only_the_unclaimed_one_is_named`.
//! * `claim keys --log "<%B>"` non-empty — a claim:
//!   `a_refs_trailer_is_a_claim_and_a_bare_subject_is_not`.
//! * the release exemption, version and changelog files only:
//!   `a_version_and_changelog_commit_owes_no_claim`.
//! * the bot exemption, `%ae` ending in the App noreply AND manifests only:
//!   `an_update_bot_bump_owes_no_claim_and_a_person_touching_the_same_paths_does`.
//! * `::error::Commit <sha8> claims no CLOUD-<n> issue: '<subject>'` — the finding,
//!   now `<sha8> claim`, a pointer: `the_finding_is_a_pointer_and_never_the_subject`.
//! * a config declaring no `[commit.claims]` judges subjects only, exactly as every
//!   consumer before this did: `a_consumer_declaring_no_claims_table_is_not_asked`.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, git_in, run, stdout, write};

/// The two exemptions, shaped as this repository's `batten.toml` declares them.
const CLAIMS: &str = "[commit.claims]\n\n\
     [[commit.claims.unclaimed]]\n\
     id = \"release\"\n\
     paths = '^(Cargo\\.(toml|lock)|.*CHANGELOG\\.md)$'\n\n\
     [[commit.claims.unclaimed]]\n\
     id = \"update-bot\"\n\
     paths = '^(\\.github/workflows/[^/]+\\.ya?ml|mise\\.(toml|lock)|Cargo\\.(toml|lock))$'\n\
     author = '\\[bot\\]@users\\.noreply\\.github\\.com$'\n";

/// An update bot's author identity, in the shape a forge mints for an App.
const BOT: &str = "renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>";

/// A repository whose config declares the subject convention, the grammar a
/// claim is read through — this repository's own rows, never re-typed — and,
/// when asked, the claims table. Returns the checkout and its base commit.
fn fixture(name: &str, claims: bool) -> (PathBuf, String) {
    let table = if claims { CLAIMS } else { "" };
    let dir = Fixture::new(name)
        .config(&format!(
            "version = 1\n\n\
             [commit]\nsubject_pattern = '^(feat|fix|chore|ci)(\\(.+\\))?!?: .+'\n\n\
             {table}\n{}",
            common::declared_patterns()
        ))
        .file("src/lib.rs", "// base\n")
        .git()
        .base_commit()
        .build();
    let base = git_in(&dir, &["rev-parse", "HEAD"]);
    (dir, base)
}

/// Write `path`, then commit it with `message`, optionally as `author`.
fn commit(dir: &Path, path: &str, message: &str, author: Option<&str>) -> String {
    write(dir, path, &format!("{message}\n"));
    git_in(dir, &["add", "-A"]);
    match author {
        Some(author) => git_in(dir, &["commit", "-q", "--author", author, "-m", message]),
        None => git_in(dir, &["commit", "-q", "-m", message]),
    };
    git_in(dir, &["rev-parse", "HEAD"])
}

/// `batten commit check <base>..HEAD`, as (exit code, stdout).
fn check(dir: &Path, base: &str) -> (Option<i32>, String) {
    let output = run(dir, &["commit", "check", &format!("{base}..HEAD")]);
    (output.status.code(), stdout(&output))
}

fn short(sha: &str) -> &str {
    &sha[..8]
}

#[test]
fn every_commit_in_the_range_is_judged_and_only_the_unclaimed_one_is_named() {
    let (dir, base) = fixture("claims-range", true);
    let claimed = commit(&dir, "src/a.rs", "feat: a\n\nRefs: CLOUD-1", None);
    let unclaimed = commit(&dir, "src/b.rs", "fix: b", None);
    let (code, out) = check(&dir, &base);
    assert_eq!(code, Some(2), "{out}");
    assert_eq!(out, format!("{} claim\n", short(&unclaimed)), "{out}");
    assert!(!out.contains(short(&claimed)), "{out}");
}

#[test]
fn a_refs_trailer_is_a_claim_and_a_bare_subject_is_not() {
    let (dir, base) = fixture("claims-trailer", true);
    commit(&dir, "src/a.rs", "feat: a\n\nRefs: CLOUD-7", None);
    let (code, out) = check(&dir, &base);
    assert_eq!(code, Some(0), "a Refs trailer claims its row: {out}");

    // The subject naming the key is a MENTION, and claiming is stricter than
    // mentioning (CLOUD-338/CLOUD-378): only the message's claim grammar counts.
    let (dir, base) = fixture("claims-subject-only", true);
    let mention = commit(&dir, "src/a.rs", "feat: a", None);
    let (code, out) = check(&dir, &base);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains(short(&mention)), "{out}");
}

#[test]
fn a_version_and_changelog_commit_owes_no_claim() {
    let (dir, base) = fixture("claims-release", true);
    write(&dir, "CHANGELOG.md", "## 1.0.0\n");
    commit(&dir, "Cargo.toml", "chore: release v1.0.0", None);
    let (code, out) = check(&dir, &base);
    assert_eq!(
        code,
        Some(0),
        "a release commit is exempt by its file set: {out}"
    );

    // And the exemption is the FILE SET, never the wording: the same subject over
    // code is judged like any other commit.
    let borrowed = commit(&dir, "src/c.rs", "chore: release v1.0.1", None);
    let (code, out) = check(&dir, &base);
    assert_eq!(code, Some(2), "{out}");
    assert!(out.contains(short(&borrowed)), "{out}");
}

#[test]
fn an_update_bot_bump_owes_no_claim_and_a_person_touching_the_same_paths_does() {
    let (dir, base) = fixture("claims-bot", true);
    commit(&dir, "mise.toml", "ci: bump a tool", Some(BOT));
    let (code, out) = check(&dir, &base);
    assert_eq!(code, Some(0), "the App's manifest bump is exempt: {out}");

    let person = commit(
        &dir,
        ".github/workflows/ci.yml",
        "ci: a workflow change",
        Some("Someone <someone@example.com>"),
    );
    let (code, out) = check(&dir, &base);
    assert_eq!(
        code,
        Some(2),
        "a workflow-only diff is ordinary work: {out}"
    );
    assert_eq!(out, format!("{} claim\n", short(&person)), "{out}");
}

#[test]
fn the_finding_is_a_pointer_and_never_the_subject() {
    let (dir, base) = fixture("claims-pointer", true);
    commit(&dir, "src/a.rs", "fix: SECRETLEAK in the subject", None);
    let (_, out) = check(&dir, &base);
    assert!(!out.contains("SECRETLEAK"), "{out}");
}

#[test]
fn a_consumer_declaring_no_claims_table_is_not_asked() {
    let (dir, base) = fixture("claims-undeclared", false);
    commit(&dir, "src/a.rs", "fix: b", None);
    let (code, out) = check(&dir, &base);
    assert_eq!(code, Some(0), "subjects only, as before: {out}");
}
