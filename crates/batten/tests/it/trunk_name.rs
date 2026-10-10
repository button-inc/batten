//! A consumer whose trunk is not named `main` (CLOUD-2188).
//!
//! Measured on a consumer whose default branch is `trunk`:
//! `claim`, `land`, `lease`, receipt currency and `perf` each read `origin/main`
//! by name, so a repository that never had a `main` could not land. The owner's
//! rule is that the consumer never renames its branch to suit Batten — so every
//! verb asks the one resolver, `worktree::land_trunk`: `must_land_on`, else the
//! remote's recorded default branch, and with neither, could-not-look.
//!
//! # The three fixtures, and why the third carries a real `origin/main`
//!
//! * origin's HEAD records `trunk` and no `must_land_on` is declared;
//! * `must_land_on` names `trunk` (in each of its three spellings) and origin's
//!   HEAD is unset;
//! * NEITHER — and `refs/remotes/origin/main` is present and real. That is the
//!   discriminating shape: a verb that fell back to `main` would find a ref
//!   that resolves and answer as though it had a trunk, so a refusal here
//!   cannot be explained by `main` failing to resolve.
//!
//! The remote's URL is an address nothing listens on, so no case reaches a
//! network: `land linear` names which ref it tried to fetch and stops there,
//! which is the half of its answer this suite is about. Its linear and behind
//! verdicts need a smart-HTTP remote and are pinned where they live.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::{Path, PathBuf};
use std::process::Output;

use crate::common::{
    Fixture, batten, declared_board, declared_patterns, git_in, run, run_with_stdin, stderr,
    stdout, write,
};

/// Where the fixture's trunk is recorded.
#[derive(Clone, Copy)]
enum Recorded {
    /// `refs/remotes/origin/HEAD` points at `origin/trunk`; nothing declared.
    OriginHead,
    /// `must_land_on` is this spelling; origin's HEAD is unset.
    Declared(&'static str),
    /// Neither — and a real `origin/main` beside the gap.
    Nowhere,
}

/// The licence table `claim carry` judges, as the engine names it.
const TABLE: &str = "mise-tasks/sbom-actions.tsv";

const BASE: &str = "tool/runner-action@aaa\tMIT\tCopyright (c) 2018 A Holder\n";

/// A checkout on `feature/claim` whose base commit is the remote trunk.
///
/// The local trunk branch is named `trunk` too, so `perf record` has one to
/// stand on; under [`Recorded::Nowhere`] the tracking ref is `origin/main`.
fn repo(name: &str, recorded: Recorded) -> PathBuf {
    let declared = match recorded {
        Recorded::Declared(spelling) => format!("must_land_on = \"{spelling}\"\n"),
        Recorded::OriginHead | Recorded::Nowhere => String::new(),
    };
    let dir = Fixture::new(name)
        .config(&format!(
            "version = 1\n{declared}\n[receipt]\nverified_by = [\"verify\", \"linear-check\"]\n\n{}\n{}",
            declared_board(),
            declared_patterns()
        ))
        .file(TABLE, BASE)
        // `claim check` reads the workspace version §6's arrows key on.
        .file(
            "Cargo.toml",
            "[workspace.package]\nversion = \"0.0.125\"\n",
        )
        .git()
        .build();
    // COMMITTED BY HAND, NOT `base_commit()`: that helper declares the pinned
    // `origin/main` the trunk, and what is declared here is the subject.
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "base policy"]);
    git_in(&dir, &["branch", "-q", "-m", "main", "trunk"]);
    git_in(
        &dir,
        &["remote", "add", "origin", "http://127.0.0.1:9/nothing.git"],
    );
    let tracking = match recorded {
        Recorded::Nowhere => "refs/remotes/origin/main",
        Recorded::OriginHead | Recorded::Declared(_) => "refs/remotes/origin/trunk",
    };
    git_in(&dir, &["update-ref", tracking, "HEAD"]);
    if matches!(recorded, Recorded::OriginHead) {
        git_in(
            &dir,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/trunk",
            ],
        );
    }
    git_in(&dir, &["checkout", "-q", "-b", "feature/claim"]);
    dir
}

fn said(output: &Output) -> String {
    format!("{}{}", stdout(output), stderr(output))
}

fn receipts(dir: &Path) -> PathBuf {
    dir.join(".git").join("batten-receipts")
}

fn sha(dir: &Path, rev: &str) -> String {
    git_in(dir, &["rev-parse", rev]).trim().to_owned()
}

/// A body that passes the readiness rule, so nothing but the trunk decides.
fn refined_body() -> String {
    "**Refinement — Ready (a summary)**\n\n\
     * **Source of truth (§1).** One authoritative artifact.\n\
     * **Commit / bump (§6).** `ci` → **no bump**.\n"
        .to_owned()
}

/// `claim check` with a pullable `Todo` row, its session stamp and read
/// receipt minted the way `claim.rs` mints them.
fn claim_check(dir: &Path) -> Output {
    let store = receipts(dir);
    std::fs::create_dir_all(&store).expect("the receipt store");
    std::fs::write(store.join("session-start"), "").expect("the session stamp");
    let scratch = dir.join(".git").join("hash-input");
    std::fs::write(&scratch, refined_body()).expect("the hash input");
    let digest = git_in(dir, &["hash-object", scratch.to_str().expect("utf-8")]);
    std::fs::remove_file(&scratch).expect("clean up the hash input");
    std::fs::write(
        store.join("issue-read.CLOUD-1"),
        format!("issue-read CLOUD-1 - {}\n", digest.trim()),
    )
    .expect("the read receipt");
    let payload = serde_json::json!({
        "id": "CLOUD-1",
        "status": "Todo",
        "description": refined_body(),
        "updatedAt": "2026-08-01T00:00:00Z",
    });
    run_with_stdin(dir, &["claim", "check"], &payload.to_string())
}

fn claim_receipt(dir: &Path) -> Option<String> {
    std::fs::read_to_string(receipts(dir).join("claim.feature-claim")).ok()
}

/// `receipt verified` after recording both receipts it asks about.
fn verified(dir: &Path) -> Output {
    for check in ["verify", "linear-check"] {
        let recorded = run(dir, &["receipt", "record", check]);
        assert!(recorded.status.success(), "{}", said(&recorded));
    }
    run(dir, &["receipt", "verified"])
}

/// One table row carried forward, committed — the `claim carry` premise.
fn carried(dir: &Path) -> Output {
    write(
        dir,
        TABLE,
        &format!("{BASE}tool/runner-action@ccc\tMIT\tCopyright (c) 2018 A Holder\n"),
    );
    git_in(dir, &["add", "-A"]);
    git_in(dir, &["commit", "-q", "-m", "ci(deps): carry"]);
    run(dir, &["claim", "carry"])
}

fn land_linear(dir: &Path) -> Output {
    run(dir, &["land", "linear"])
}

fn lease_carries(dir: &Path) -> Output {
    let head = sha(dir, "HEAD");
    batten()
        .env_remove("LEASE_TRUNK")
        .args(["lease", "carries", &head])
        .current_dir(dir)
        .output()
        .expect("run batten lease carries")
}

fn perf_record(dir: &Path) -> Output {
    batten()
        .env_remove("BENCH_TRUNK")
        .args(["perf", "record"])
        .current_dir(dir)
        .stdin(std::process::Stdio::null())
        .output()
        .expect("run batten perf record")
}

/// The answers a resolved `trunk` must give, asked of one fixture: the same
/// ones a fixture named `main` gives.
fn assert_resolves_trunk(dir: &Path) {
    let trunk = sha(dir, "refs/remotes/origin/trunk");

    let claimed = claim_check(dir);
    assert_eq!(claimed.status.code(), Some(0), "{}", said(&claimed));
    let receipt = claim_receipt(dir).expect("the claim receipt is minted");
    assert!(
        receipt.contains(&format!("\nbase {trunk}")),
        "the base is the trunk's tip: {receipt}"
    );

    let answer = verified(dir);
    assert_eq!(answer.status.code(), Some(0), "{}", said(&answer));

    let linear = land_linear(dir);
    assert!(
        said(&linear).contains("could not fetch trunk"),
        "an unnamed reference is the declared trunk: {}",
        said(&linear)
    );

    let carry = carried(dir);
    assert_eq!(carry.status.code(), Some(0), "{}", said(&carry));

    git_in(dir, &["checkout", "-q", "trunk"]);
    let on_trunk = perf_record(dir);
    assert!(
        !said(&on_trunk).contains("not the trunk"),
        "`trunk` is the trunk: {}",
        said(&on_trunk)
    );
    git_in(dir, &["checkout", "-q", "-b", "elsewhere"]);
    let off_trunk = perf_record(dir);
    assert!(
        said(&off_trunk).contains("not the trunk"),
        "the premise: a branch is refused: {}",
        said(&off_trunk)
    );
}

/// Acceptance 1: origin's HEAD alone names the trunk.
#[test]
fn origin_head_names_the_trunk_when_nothing_is_declared() {
    assert_resolves_trunk(&repo("trunk-name-origin-head", Recorded::OriginHead));
}

/// Acceptance 2, and `#MUTANT must-land-on-ignored` reddens here: with origin's
/// HEAD unset, only the declaration can name the trunk — in every spelling.
#[test]
fn must_land_on_names_the_trunk_when_origin_head_is_unset() {
    for (index, spelling) in ["origin/trunk", "trunk", "refs/remotes/origin/trunk"]
        .into_iter()
        .enumerate()
    {
        let dir = repo(
            &format!("trunk-name-declared-{index}"),
            Recorded::Declared(spelling),
        );
        assert_resolves_trunk(&dir);
    }
}

/// Acceptance 3, and `#MUTANT trunk-name-falls-back-to-main` reddens here: no
/// declaration, no recorded HEAD, and a REAL `origin/main` that a fallback would
/// find. Each verb takes its could-not-look path and names the gap.
#[test]
fn an_unresolvable_trunk_is_refused_not_assumed() {
    let dir = repo("trunk-name-nowhere", Recorded::Nowhere);
    assert!(
        !sha(&dir, "refs/remotes/origin/main").is_empty(),
        "the premise: origin/main resolves"
    );

    let claimed = claim_check(&dir);
    assert_eq!(claimed.status.code(), Some(1), "{}", said(&claimed));
    assert!(said(&claimed).contains("no trunk"), "{}", said(&claimed));
    assert_eq!(claim_receipt(&dir), None, "no receipt with no base");

    let receipt = run(&dir, &["receipt", "verified"]);
    assert_eq!(receipt.status.code(), Some(1), "{}", said(&receipt));
    assert!(said(&receipt).contains("no trunk"), "{}", said(&receipt));

    let linear = land_linear(&dir);
    assert_eq!(linear.status.code(), Some(3), "{}", said(&linear));
    assert!(said(&linear).contains("no trunk"), "{}", said(&linear));
    assert!(
        !said(&linear).contains("fetch main"),
        "never reads main: {}",
        said(&linear)
    );

    let lease = lease_carries(&dir);
    assert_eq!(
        lease.status.code(),
        Some(3),
        "exit 3 is run: {}",
        said(&lease)
    );
    assert!(said(&lease).contains("no trunk"), "{}", said(&lease));

    let carry = run(&dir, &["claim", "carry"]);
    assert_eq!(carry.status.code(), Some(1), "{}", said(&carry));
    assert!(said(&carry).contains("no trunk"), "{}", said(&carry));
}
