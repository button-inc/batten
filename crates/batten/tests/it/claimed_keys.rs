//! `claim keys` and `claim merged`, over the compiled binary (CLOUD-1711, CLOUD-1752).
//!
//! # RETIREMENT LEDGER, PER PATH — what `shell-retirement` reads
//!
//! A program and its suite are TWO rows, never one.

// carried: mise-tasks/claimed-keys.sh crates/batten/src/race.rs kind:mechanism crates/batten/tests/it/claimed_keys.rs runs:batten+claim+keys
// carried: tests/claimed-keys.bats crates/batten/src/race.rs kind:mechanism crates/batten/tests/it/claimed_keys.rs
// carried: mise-tasks/merged-pr-keys.sh crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/claimed_keys.rs runs:batten+claim+merged
// carried: tests/merged-pr-keys.bats crates/batten/src/forge.rs kind:mechanism crates/batten/tests/it/claimed_keys.rs

// --- claimed-keys.bats, case by case ---------------------------------------
// carried: "a branch naming one issue is an unambiguous claim" crates/batten/src/race.rs kind:mechanism
// carried: "a closing keyword on stdin overrides the branch" crates/batten/src/race.rs kind:mechanism
// carried: "a closing keyword in a commit overrides the branch too" crates/batten/src/race.rs kind:mechanism
// carried: "a merely mentioned issue is not a claim" crates/batten/src/race.rs kind:mechanism
// carried: "a Refs: trailer claims when nothing more explicit does" crates/batten/src/race.rs kind:mechanism
// carried: "nothing resolvable is an empty answer, not an error" crates/batten/src/race.rs kind:mechanism
// carried: "outside a git checkout it exits 0 and says nothing" crates/batten/src/race.rs kind:mechanism
// carried: "the answer is uppercased and deduplicated" crates/batten/src/race.rs kind:mechanism
// carried: "output is the keys alone — never the prose they came from" crates/batten/src/race.rs kind:mechanism
// carried: "an explicit branch answers instead of the checkout's" crates/batten/src/race.rs kind:mechanism
// carried: "an explicit title is a claim, the way a branch is" crates/batten/src/race.rs kind:mechanism
// carried: "branch and title are a union, not a precedence between them" crates/batten/src/race.rs kind:mechanism
// carried: "a body that merely CITES a key claims nothing — the measured case" crates/batten/src/race.rs kind:mechanism
// carried: "a closing keyword in an explicit body still overrides branch and title" crates/batten/src/race.rs kind:mechanism
// carried: "an explicit log supplies the Refs: trailer, and only the trailer" crates/batten/src/race.rs kind:mechanism
// carried: "a key merely cited in an explicit log claims nothing" crates/batten/src/race.rs kind:mechanism
// carried: "explicit mode is all-or-nothing — an unsupplied source is empty, never local" crates/batten/src/race.rs kind:mechanism
// carried: "a key carried only by a speculated commit is not claimed" crates/batten/src/race.rs kind:mechanism
// carried: "a key this branch authored is still claimed with a speculation live" crates/batten/src/race.rs kind:mechanism
// carried: "with no speculation live the answer is exactly what it was" crates/batten/src/race.rs kind:mechanism
// carried: "a spec base that is not an ancestor of HEAD is ignored" crates/batten/src/race.rs kind:mechanism
// carried: "--closing-only does not fall through to a Refs: trailer" crates/batten/src/race.rs kind:mechanism
// carried: "--closing-only does not fall through to the branch name" crates/batten/src/race.rs kind:mechanism
// carried: "--closing-only still answers on a closing keyword" crates/batten/src/race.rs kind:mechanism
// carried: "without --closing-only the fallback chain is unchanged" crates/batten/src/race.rs kind:mechanism
// carried: "--closing-only reads the log from stdin, which is how a 1.27MB history fits" crates/batten/src/race.rs kind:mechanism
// carried: "--refs-first-only ignores a closing keyword in the body" crates/batten/src/race.rs kind:mechanism
// carried: "--refs-first-only takes the first key of the trailer, not its citations" crates/batten/src/race.rs kind:mechanism
// carried: "--refs-first-only ignores the branch name too" crates/batten/src/race.rs kind:mechanism
// carried: "--refs-first-only with no trailer answers empty, which is 'do not judge'" crates/batten/src/race.rs kind:mechanism
// changed: "a flag with no value is exit 2, never a silently empty source" crates/batten/src/race.rs kind:mechanism the engine parses its own arguments, so a value-less flag is refused by the parser before this verb runs, at Usage (1) rather than the shell's 2 — the contract inversion this campaign deliberately does not carry across
// changed: "an unknown argument is exit 2, and names no prose" crates/batten/src/race.rs kind:mechanism same route: the parser refuses an unknown flag at Usage (1). It still names no prose, which is the half that was about rule 4 rather than about the code
// changed: "the two narrowing flags are mutually exclusive" crates/batten/src/race.rs kind:mechanism carried as a decision and re-coded: `run_claim_merged`'s sibling `run_claim_keys` refuses both flags at Usage (1), not the shell's 2

// --- merged-pr-keys.bats, case by case --------------------------------------
// carried: "a closing keyword in a merged body emits one row" crates/batten/src/forge.rs kind:mechanism
// carried: "Fixes and Resolves are claims too" crates/batten/src/forge.rs kind:mechanism
// carried: "a Refs: trailer is a mention and emits nothing" crates/batten/src/forge.rs kind:mechanism
// carried: "a bare citation in prose emits nothing" crates/batten/src/forge.rs kind:mechanism
// carried: "several keys in one body emit several rows, all keyed to that PR" crates/batten/src/forge.rs kind:mechanism
// carried: "a null body is data, not a crash" crates/batten/src/forge.rs kind:mechanism
// carried: "two runs over the same reading are byte-identical" crates/batten/src/forge.rs kind:mechanism
// carried: "a reading at the fetch limit is refused as truncated, not returned short" crates/batten/src/forge.rs kind:mechanism
// carried: "a reading below the fetch limit is answered" crates/batten/src/forge.rs kind:mechanism
// carried: "an empty forge answer is could-not-look, never an empty evidence file" crates/batten/src/forge.rs kind:mechanism
// carried: "output carries no PR body" crates/batten/src/forge.rs kind:mechanism
// changed: "an unreadable source is exit 2" crates/batten/src/forge.rs kind:mechanism the `MERGED_PR_KEYS_SOURCE` file seam is gone: the transport is `forge::window`, whose test seam is an injected `Transport` rather than a saved payload path. An unreadable forge is `Window::CouldNotLook` and exits 3 — fail loud, do not block — where the shell used its own 2
// changed: "a source that is not a JSON array is exit 2" crates/batten/src/forge.rs kind:mechanism same seam. A body that will not parse is `Window::CouldNotLook`, exit 3; the decision (unparseable is could-not-look, never an empty collection) is carried verbatim
// changed: "a non-numeric limit is a caller bug, not a default" crates/batten/src/forge.rs kind:mechanism carried as a decision at a different code: `--limit` that is not a positive number is Usage (1), never silently the default

//! # Why these cases
//!
//! The discriminating case is the CITATION TRAP, and it is what the retired
//! program existed for: a body cites related issues, prior measurements and
//! superseded work as evidence, and reading a citation as a claim made a pull
//! request race the very key it cited. Both sides of every comparison go through
//! one function for exactly that reason.
//!
//! The second is TRUNCATION. `merged-pr-keys` refused a reading at its fetch
//! limit rather than answering short, because a truncated evidence file makes
//! landed work read as live — measured at `--limit 400`, which returned exactly
//! 400 and hid three pull requests.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use common::{git_in, run_with_stdin, scratch, stderr, stdout, write};

/// A repository whose branch names a key, with one commit carrying a trailer.
///
/// **Carries this repository's OWN `batten.toml`**, because the decisions under
/// test are the consumer's: which token is a key, which verb closes one, and
/// which negates it all live in `[[pattern]]` rows. A fixture with a hand-written
/// subset would assert against a grammar no checkout has, which is the fabricated
/// shape CLOUD-845 records one layer up.
fn repo(name: &str, branch: &str) -> std::path::PathBuf {
    let dir = scratch(&format!("claim-keys-{name}"));
    let config = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("batten.toml");
    std::fs::copy(&config, dir.join("batten.toml")).expect("the committed config is readable");
    write(&dir, "seed.txt", "seed\n");
    git_in(&dir, &["init", "-q", "-b", "main", "."]);
    git_in(&dir, &["add", "-A"]);
    git_in(
        &dir,
        &[
            "commit",
            "-qm",
            "chore: seed\n\nRefs: CLOUD-4242, CLOUD-9\n",
        ],
    );
    if !branch.is_empty() {
        git_in(&dir, &["checkout", "-q", "-b", branch]);
    }
    dir
}

fn keys(dir: &std::path::Path, args: &[&str], stdin: &str) -> std::process::Output {
    let mut command = vec!["claim", "keys"];
    command.extend_from_slice(args);
    run_with_stdin(dir, &command, stdin)
}

#[test]
fn a_body_that_cites_a_key_without_closing_it_does_not_claim_it() {
    // THE MEASURED CASE, and the whole reason the program existed. PR #306 cited
    // CLOUD-133 in one row of an evidence table and was reported as claiming it.
    let dir = repo("cites", "");
    let out = keys(
        &dir,
        &["--branch", "", "--title", "", "--log", ""],
        "Supersedes the measurement in CLOUD-133.\n",
    );
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "", "citing is not claiming");
}

#[test]
fn a_closing_keyword_in_the_body_is_a_claim() {
    // The anti-vacuity mirror: without it, a verb that answered empty for every
    // input would pass the citation case.
    let dir = repo("closes", "");
    let out = keys(
        &dir,
        &["--branch", "", "--title", "", "--log", ""],
        "Closes CLOUD-133.\n",
    );
    assert_eq!(stdout(&out).trim(), "CLOUD-133");
}

#[test]
fn branch_and_title_are_a_union_rather_than_a_precedence() {
    // Two spellings of ONE self-declaration. Picking one would make the answer
    // depend on which the author happened to fill in.
    let dir = repo("union", "");
    let out = keys(
        &dir,
        &[
            "--branch",
            "user/cloud-1-thing",
            "--title",
            "a fix (CLOUD-2)",
            "--log",
            "",
        ],
        "",
    );
    let answer = stdout(&out);
    assert!(answer.contains("CLOUD-1"), "{answer}");
    assert!(answer.contains("CLOUD-2"), "{answer}");
}

#[test]
fn explicit_mode_is_all_or_nothing_and_never_falls_back_to_the_checkout() {
    // A remote pull request silently answered from the LOCAL branch is the worst
    // kind of wrong: a confident verdict about the wrong repository state.
    let dir = repo("explicit", "user/cloud-999-local");
    let out = keys(&dir, &["--title", "a title with no key"], "");
    assert_eq!(
        stdout(&out).trim(),
        "",
        "an unsupplied source is EMPTY in explicit mode, never the checkout's branch"
    );
}

#[test]
fn the_two_narrowing_flags_are_mutually_exclusive() {
    // Each names a different SINGLE source, so both together is a caller that has
    // not decided which question it is asking. USAGE (1), not the shell's 2 — the
    // contract inversion this campaign does not carry across.
    let dir = repo("both-flags", "");
    let out = keys(&dir, &["--closing-only", "--refs-first-only"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}

#[test]
fn refs_first_only_ignores_a_closing_keyword_in_the_body() {
    // CLOUD-674's circularity: the SERVED set must be derived without reference
    // to the closing keys, or it agrees with the body by construction and
    // `closing-key-check` passes on exactly the bodies it must refuse.
    let dir = repo("refs-only", "");
    let out = keys(
        &dir,
        &[
            "--refs-first-only",
            "--branch",
            "",
            "--title",
            "",
            "--log",
            "Refs: CLOUD-77, CLOUD-88\n",
        ],
        "Closes CLOUD-99.\n",
    );
    let answer = stdout(&out);
    assert!(
        answer.contains("CLOUD-77"),
        "the trailer's FIRST key\n{answer}"
    );
    assert!(
        !answer.contains("CLOUD-88"),
        "citing after it is not claiming\n{answer}"
    );
    assert!(
        !answer.contains("CLOUD-99"),
        "source 1 must not answer here\n{answer}"
    );
}

#[test]
fn closing_only_never_falls_through_to_the_branch_or_a_trailer() {
    let dir = repo("closing-only", "");
    let out = keys(
        &dir,
        &[
            "--closing-only",
            "--branch",
            "user/cloud-5-x",
            "--title",
            "",
            "--log",
            "Refs: CLOUD-6\n",
        ],
        "",
    );
    assert_eq!(stdout(&out).trim(), "", "{}", stderr(&out));
}

#[test]
fn outside_a_git_checkout_it_says_nothing_and_does_not_fail() {
    // Every caller reads "no claim" as "do not judge", because a guard that
    // guesses is one that blocks correct work.
    // OUTSIDE THE REPOSITORY'S OWN TREE, deliberately: `scratch` lives under
    // `target/`, so git discovery walks up and finds THIS checkout — which is the
    // opposite of what this case is about. Measured: it answered with this
    // branch's own keys.
    let dir = std::env::temp_dir().join("batten-claim-keys-nogit");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a directory outside any checkout");
    let config = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("batten.toml");
    std::fs::copy(&config, dir.join("batten.toml")).expect("the committed config is readable");
    let out = keys(&dir, &[], "");
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert_eq!(stdout(&out).trim(), "");
}

#[test]
fn a_non_numeric_merged_limit_is_a_caller_bug_rather_than_the_default() {
    // Silently falling back to 5000 would answer a different question than the
    // caller asked, and the answer would look authoritative.
    let dir = repo("merged-limit", "");
    let out = run_with_stdin(&dir, &["claim", "merged", "--limit", "lots"], "");
    assert_eq!(out.status.code(), Some(1), "{}", stderr(&out));
}
