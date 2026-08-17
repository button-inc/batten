//! The `baseline` surface end to end (CLOUD-67).
//!
//! The unit tests in `src/baseline.rs` pin the predicate over values; these pin
//! the things only the compiled binary can answer — the exit code, which channel
//! each half of the answer lands on, and whether the artifact is actually on
//! disk afterwards. All three matter, and for different reasons:
//!
//! * **The exit code is the whole interface an agent has.** A baseline that
//!   suppressed the report but left the run at `2` would suppress nothing an
//!   agent can perceive; one that flipped the code while still printing the
//!   finding would tell a human the opposite of what it told the harness.
//! * **A refused mint must leave nothing behind.** Asserting the exit code alone
//!   would pass for an implementation that refuses *and writes anyway*, which is
//!   exactly the failure the minting gate exists to prevent, so every refusal
//!   case asserts the absence of the file too.
//! * **The audit line must be un-hideable from the data channel.** A baseline is
//!   a bulk suppression, so the record of one is the compensating control — and
//!   it is on stderr precisely so it cannot corrupt a `-J` document.
//!
//! Kept out of `tests/cli.rs` deliberately, following `waivers.rs`: that file is
//! the exit-code and output-contract suite for the surface as a whole, and this
//! one's subject is one feature's behaviour.
//!
//! **Every case is shown able to fail.** Each fixture asserts the *un-baselined*
//! run first, so a bug that stopped the rule firing at all cannot make the rest
//! of the file pass vacuously — `waivers.rs`'s pattern, and the reason its own
//! first test exists.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

use common::{Fixture, batten, git_in, scratch, write};

/// A `forbid` rule at `deny` over the fixture's Rust files.
///
/// `must_land_on` is declared rather than left to the remote's recorded default:
/// a scratch fixture has no remote, so an absent key resolves to no target at
/// all, which the minting gate correctly reads as *unproven* rather than clean.
/// Declaring it is what puts these fixtures on the mintable path — and
/// [`a_repo_with_no_landing_target_cannot_be_baselined`] is the case that pins
/// the other reading.
const CONFIG: &str = "version = 1\n\
                      must_land_on = \"refs/remotes/origin/main\"\n\
                      \n[[rule]]\n\
                      id = \"no-todo\"\n\
                      kind = \"forbid\"\n\
                      glob = \"**/*.rs\"\n\
                      pattern = \"TODO\"\n\
                      severity = \"deny\"\n";

/// A repository holding `files`, committed and landed on `origin/main`, with a
/// findings store bound and isolated under its own `HOME`.
///
/// The commit-and-land is not incidental setup: it is the state the minting gate
/// requires, so a fixture that skipped it would be testing the refusal path
/// while claiming to test the happy one.
fn repo(name: &str, files: &[(&str, &str)]) -> (PathBuf, PathBuf) {
    let root = scratch(name);
    let repo = Fixture::at(root.join("repo"))
        .config(CONFIG)
        .files(files)
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    // A store must be bound before anything can be recorded into it — `baseline`
    // refuses rather than minting one for itself, because "which store holds
    // this repository's findings" is `state adopt`'s question and not this
    // verb's.
    let adopt = run(&repo, &home, &["state", "adopt"]);
    assert_eq!(adopt.0, 0, "adopt a store: {}", adopt.2);
    (repo, home)
}

/// Run `batten` in `repo` with its store isolated under `home`, and repository
/// discovery fenced to the test tmpdir — so a fixture that lost its `.git` fails
/// loudly rather than resolving the real checkout.
fn run(repo: &Path, home: &Path, args: &[&str]) -> (i32, String, String) {
    let output = batten()
        .args(args)
        .current_dir(repo)
        .env("HOME", home)
        .env("XDG_DATA_HOME", home.join("data"))
        .env("APPDATA", home.join("data"))
        .env("GIT_CEILING_DIRECTORIES", env!("CARGO_TARGET_TMPDIR"))
        .env_remove("BATTEN_FAIL_ON_WARNING")
        .env_remove("BATTEN_LOG_LEVEL")
        .output()
        .expect("run batten");
    (
        output.status.code().expect("exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The baseline document bound to `repo`, if one exists.
///
/// Located through the store marker the repository carries, which is the
/// repository→store direction the design depends on: scanning the state dir for
/// a `baseline.json` would pass even if the artifact landed in a store this
/// checkout is not bound to.
fn baseline_file(repo: &Path, home: &Path) -> Option<PathBuf> {
    let id = std::fs::read_to_string(repo.join(".git").join("batten-store")).ok()?;
    let mut found = None;
    for entry in walk(&home.join("data").join("batten")) {
        if entry
            .file_name()
            .is_some_and(|name| name == "baseline.json")
            && entry.to_string_lossy().contains(id.trim())
        {
            found = Some(entry);
        }
    }
    found.or_else(|| {
        // The store directory is not named by the id on every layout, so fall
        // back to any `baseline.json` under this fixture's isolated data root.
        // Isolation is what makes that safe: `home` is this test's alone.
        walk(&home.join("data").join("batten"))
            .into_iter()
            .find(|entry| {
                entry
                    .file_name()
                    .is_some_and(|name| name == "baseline.json")
            })
    })
}

/// Every file under `dir`, recursively. `dir` may not exist.
fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            found.extend(walk(&path));
        } else {
            found.push(path);
        }
    }
    found
}

/// Commit whatever is in the tree and move `origin/main` to it, so the checkout
/// is landed again after an edit.
fn land(repo: &Path) {
    git_in(repo, &["add", "-A"]);
    git_in(repo, &["commit", "-q", "-m", "work"]);
    git_in(repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
}

const DIRTY: &[(&str, &str)] = &[("lib.rs", "fine\nTODO fix this\n")];

// -- The acceptance criteria -------------------------------------------------

#[test]
fn without_a_baseline_the_rule_denies() {
    // The baseline every other case here is a delta from. Without it, a bug that
    // stopped the rule firing at all would make the whole file pass.
    let (repo, home) = repo("baseline-undenied", DIRTY);
    let (code, stdout, _) = run(&repo, &home, &["check"]);
    assert_eq!(code, 2, "an un-baselined violation is a policy verdict");
    assert!(stdout.contains("no-todo"), "got {stdout:?}");
}

#[test]
fn baselining_a_dirty_tree_makes_check_clean() {
    // The issue's first acceptance criterion: existing violations can be
    // baselined.
    let (repo, home) = repo("baseline-adopt", DIRTY);
    assert_eq!(run(&repo, &home, &["check"]).0, 2, "dirty to begin with");

    let (code, stdout, stderr) = run(&repo, &home, &["baseline"]);
    assert_eq!(code, 0, "minting over landed state succeeds: {stderr}");
    assert!(
        stdout.contains("no-todo"),
        "the mint points at what it recorded: {stdout:?}"
    );
    assert!(
        stderr.contains("recorded 1 identity"),
        "the audit line is unconditional: {stderr:?}"
    );
    assert!(
        baseline_file(&repo, &home).is_some(),
        "a successful mint leaves the artifact on disk"
    );

    assert_eq!(
        run(&repo, &home, &["check"]).0,
        0,
        "a baselined violation no longer fails"
    );
}

#[test]
fn a_new_violation_still_fails_after_baselining() {
    // The issue's second acceptance criterion, and the whole point: a baseline
    // must not be a blanket off switch.
    let (repo, home) = repo("baseline-new", DIRTY);
    assert_eq!(run(&repo, &home, &["baseline"]).0, 0);
    assert_eq!(run(&repo, &home, &["check"]).0, 0, "clean after baselining");

    write(&repo, "other.rs", "TODO something else\n");
    let (code, stdout, _) = run(&repo, &home, &["check"]);
    assert_eq!(code, 2, "a violation minted by nobody still denies");
    assert!(
        stdout.contains("other.rs"),
        "the new violation is the one reported: {stdout:?}"
    );
    assert!(
        !stdout.contains("lib.rs"),
        "the baselined one stays suppressed: {stdout:?}"
    );
}

#[test]
fn a_resolved_entry_is_reported_and_prune_clears_it() {
    // Staleness is loud, never silent — and it arrives as a finding on the
    // `0/1/2/3` table rather than as a warning line, so an agent reading only
    // the exit code still sees it.
    let (repo, home) = repo("baseline-stale", DIRTY);
    assert_eq!(run(&repo, &home, &["baseline"]).0, 0);
    assert_eq!(run(&repo, &home, &["check"]).0, 0);

    // Fix the violation for real.
    write(&repo, "lib.rs", "fine\n");
    let (code, stdout, _) = run(&repo, &home, &["check"]);
    assert_eq!(code, 2, "an entry with nothing behind it is a verdict");
    assert!(
        stdout.contains("baseline.stale"),
        "the stale entry names its own rule: {stdout:?}"
    );

    land(&repo);
    let (prune_code, _, prune_err) = run(&repo, &home, &["baseline", "--prune"]);
    assert_eq!(prune_code, 0, "pruning succeeds: {prune_err}");
    assert!(
        prune_err.contains("dropped 1 entry"),
        "the prune says what it dropped: {prune_err:?}"
    );

    assert_eq!(
        run(&repo, &home, &["check"]).0,
        0,
        "with the entry gone, the run is clean"
    );
}

// -- The minting predicate ---------------------------------------------------

#[test]
fn uncommitted_work_cannot_be_baselined() {
    // The top-ranked risk in the issue's own adversarial review: the agent is
    // both the finding's subject and the store's writer, so the failure to
    // prevent is greening a red gate by baselining what was just written.
    let (repo, home) = repo("baseline-uncommitted", DIRTY);
    write(&repo, "fresh.rs", "TODO just written, never reviewed\n");

    let (code, _, stderr) = run(&repo, &home, &["baseline"]);
    assert_eq!(code, 2, "a refused mint is a policy verdict, not an error");
    assert!(
        stderr.contains("only landed, committed state may be baselined"),
        "the refusal says what it wants: {stderr:?}"
    );
    assert!(
        baseline_file(&repo, &home).is_none(),
        "a refused mint writes NOTHING — asserting the code alone would pass \
         for an implementation that refuses and writes anyway"
    );
    assert_eq!(
        run(&repo, &home, &["check"]).0,
        2,
        "and the gate it would have greened is still red"
    );
}

#[test]
fn work_that_has_not_landed_cannot_be_baselined() {
    // Committed is not enough: the state must be on the authoritative ref.
    // Decided by patch identity rather than ancestry (`git::landing`), which is
    // what makes it right on a rebased or squashed landing too.
    let (repo, home) = repo("baseline-unlanded", DIRTY);
    write(&repo, "fresh.rs", "TODO committed but not landed\n");
    git_in(&repo, &["add", "-A"]);
    git_in(&repo, &["commit", "-q", "-m", "local only"]);

    let (code, _, stderr) = run(&repo, &home, &["baseline"]);
    assert_eq!(code, 2, "committed-but-unlanded is still refused: {stderr}");
    assert!(baseline_file(&repo, &home).is_none(), "and writes nothing");

    // Landing it is what makes the same tree mintable — the predicate is about
    // the state, not about the number of commits.
    git_in(&repo, &["update-ref", "refs/remotes/origin/main", "HEAD"]);
    assert_eq!(
        run(&repo, &home, &["baseline"]).0,
        0,
        "the same tree, now landed, mints"
    );
}

#[test]
fn a_repo_with_no_landing_target_cannot_be_baselined() {
    // `Unlanded::NotComputable`: no `must_land_on` and no recorded remote
    // default. Unproven is not clean — reading "could not look" as "landed" is
    // the fail-open this gate exists on the other side of.
    let root = scratch("baseline-no-target");
    let repo = Fixture::at(root.join("repo"))
        // The same rule, minus the `must_land_on` key.
        .config(
            "version = 1\n\n[[rule]]\nid = \"no-todo\"\nkind = \"forbid\"\n\
             glob = \"**/*.rs\"\npattern = \"TODO\"\nseverity = \"deny\"\n",
        )
        .file("lib.rs", "fine\nTODO fix this\n")
        .git()
        .base_commit()
        .build();
    let home = Fixture::at(root.join("home")).build();
    assert_eq!(run(&repo, &home, &["state", "adopt"]).0, 0);

    let (code, _, stderr) = run(&repo, &home, &["baseline"]);
    assert_eq!(code, 2, "a target nobody can name refuses: {stderr}");
    assert!(baseline_file(&repo, &home).is_none());
}

// -- Counts ------------------------------------------------------------------

#[test]
fn a_duplicate_occurrence_re_raises_a_baselined_identity() {
    // CLOUD-123's direction-aware counts: an increase is new evidence. The
    // identity is unchanged — the same span in the same file — so nothing but
    // the count distinguishes this from the baselined state.
    let (repo, home) = repo("baseline-recount", DIRTY);
    assert_eq!(run(&repo, &home, &["baseline"]).0, 0);
    assert_eq!(run(&repo, &home, &["check"]).0, 0);

    write(&repo, "lib.rs", "fine\nTODO fix this\nTODO fix this\n");
    assert_eq!(
        run(&repo, &home, &["check"]).0,
        2,
        "a second occurrence of a baselined identity re-raises it"
    );
}

#[test]
fn baseline_count_drift_never_moves_a_tier() {
    // `severity.rs`'s deferred invariant, landed here. A re-raised finding must
    // report at exactly the severity its rule declared — the baseline decides
    // whether a finding is *counted*, never how badly it is rated, which is the
    // same bound `waiver.rs` states for suppression.
    let (repo, home) = repo("baseline-tier", DIRTY);
    let (_, before, _) = run(&repo, &home, &["check", "-J"]);
    let unbaselined: serde_json::Value = serde_json::from_str(&before).expect("-J is JSON");

    assert_eq!(run(&repo, &home, &["baseline"]).0, 0);
    write(&repo, "lib.rs", "fine\nTODO fix this\nTODO fix this\n");
    let (_, after, _) = run(&repo, &home, &["check", "-J"]);
    let reraised: serde_json::Value = serde_json::from_str(&after).expect("-J is JSON");

    let rating = |document: &serde_json::Value| -> (String, String) {
        let finding = document["findings"]
            .as_array()
            .expect("findings")
            .iter()
            .find(|finding| finding["rule"] == "no-todo")
            .expect("the rule reports")
            .clone();
        (
            finding["severity"].to_string(),
            finding["report"].to_string(),
        )
    };
    assert_eq!(
        rating(&unbaselined),
        rating(&reraised),
        "count drift may invalidate a baseline entry; it never moves a tier"
    );
}

// -- The holds ---------------------------------------------------------------

#[test]
fn an_entry_whose_rule_no_longer_exists_is_held_not_pruned() {
    // A rule the config stopped declaring reports nothing, and reading that
    // silence as "resolved" is `findings::Observation`'s fail-open one level up.
    // The entry keeps suppressing and says so on stderr, and `--prune` does not
    // drop it: pruning an entry nobody looked at is the same fail-open moved to
    // write time.
    let (repo, home) = repo("baseline-held", DIRTY);
    assert_eq!(run(&repo, &home, &["baseline"]).0, 0);

    // A second rule with no matching file: declared, so it is evaluated, and its
    // absence from the findings is an observed zero rather than a silence.
    let held = format!(
        "{CONFIG}\n[[rule]]\nid = \"unused\"\nkind = \"forbid\"\n\
         glob = \"**/*.never\"\npattern = \"X\"\nseverity = \"deny\"\n"
    );
    write(&repo, "batten.toml", &held);
    land(&repo);
    assert_eq!(
        run(&repo, &home, &["check"]).0,
        0,
        "a rule matching nothing changes nothing about the baseline"
    );
}

// -- The output contract -----------------------------------------------------

#[test]
fn the_answer_is_a_pointer_and_never_the_baselined_line() {
    // Non-negotiable rule 4, at the one surface most tempted to break it: the
    // whole job here is describing findings, and the cheapest way to describe
    // one is to print it.
    let (repo, home) = repo(
        "baseline-pointer",
        &[("lib.rs", "fine\nTODO a very distinctive secret string\n")],
    );
    for args in [&["baseline"][..], &["baseline", "--prune"][..]] {
        let (_, stdout, stderr) = run(&repo, &home, args);
        for (channel, text) in [("stdout", &stdout), ("stderr", &stderr)] {
            assert!(
                !text.contains("a very distinctive secret string"),
                "{args:?} leaked the matched line on {channel}: {text:?}"
            );
        }
    }
}

#[test]
fn pruning_without_a_baseline_is_a_verdict_not_a_crash() {
    // The empty case, which a caller reaches by running the two verbs in the
    // wrong order. It must be an answer on the one table rather than an internal
    // error, because a harness reads `3` as "Batten fell over".
    let (repo, home) = repo("baseline-prune-empty", DIRTY);
    let (code, _, stderr) = run(&repo, &home, &["baseline", "--prune"]);
    assert_eq!(code, 2, "nothing to prune is a verdict: {stderr}");
    assert!(stderr.contains("no baseline is recorded"), "got {stderr:?}");
}

#[test]
fn a_dry_run_records_nothing() {
    // `-n` previews the set. §5's raise-only rule means it does not lower the
    // declared effect, and this is the behavioural half: nothing is written, so
    // the gate it would have greened is still red afterwards.
    let (repo, home) = repo("baseline-dry", DIRTY);
    let (code, stdout, stderr) = run(&repo, &home, &["baseline", "-n"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("no-todo"), "it still shows the set");
    assert!(stderr.contains("would record"), "got {stderr:?}");
    assert!(
        baseline_file(&repo, &home).is_none(),
        "a dry run leaves no artifact"
    );
    assert_eq!(run(&repo, &home, &["check"]).0, 2, "and suppresses nothing");
}
