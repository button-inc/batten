//! What a stopped lap TELLS the person who has to act on it (CLOUD-861, CLOUD-727).
//!
//! # Why this tier exists
//!
//! `run_land_verify`'s refusal arm printed one unconditional line, so three very
//! different failures were reported identically: a gate that refused about this
//! tree, a gate that died of the machine, and a gate that refused over a tree
//! carrying commits this branch did not write. Two of the three were told to
//! reproduce and fix locally, which is a wasted cycle in one case and a hunt
//! through somebody else's diff in the other.
//!
//! Both were measured rather than imagined. `mise-tasks/land.sh` carried four
//! cases pinning them (`CLOUD-861: an ENOSPC during verify is reported as the
//! environment…`, `a verify failure on a SPECULATIVE tree names the borrowed
//! base`, and each one's anti-vacuity twin) and the engine carried no successor
//! for any of them, which is what blocked that program's retirement.
//!
//! # Each case has its twin, and that is the whole design
//!
//! Every narrowing here can be got wrong in the same way: by swallowing the
//! general case. A classifier that called every refusal environmental would turn
//! every stop into *check your disk*, which is CLOUD-811's misattribution rebuilt
//! facing the other way. So no case asserts only that the new line appears — each
//! asserts the OTHER line does not, and its twin asserts the reverse.

#![cfg(unix)]
// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

/// A gate that fails, printing whatever the case needs on the way.
///
/// Failing is the precondition every case here shares: this file is about which
/// ADVICE a refusal earns, so a gate that passed would exercise nothing.
fn failing_gate(dir: &std::path::Path, says: &str) -> String {
    let gate = dir.join("gate.sh");
    std::fs::write(
        &gate,
        format!("#!/usr/bin/env bash\nprintf '%s\\n' {says}\nexit 1\n"),
    )
    .expect("write the gate");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&gate, std::fs::Permissions::from_mode(0o755))
            .expect("make the gate runnable");
    }
    gate.to_string_lossy().into_owned()
}

/// A repository whose committed authority declares the disk-full classifier.
///
/// The row is written here rather than assumed from this repository's own
/// `batten.toml`, because a case reading the real one would pass for the wrong
/// reason the day somebody edits it — and because the whole point of the table is
/// that the literal is the CONSUMER's.
fn repo(name: &str, declare_classifier: bool) -> std::path::PathBuf {
    let classifier = if declare_classifier {
        "\n[[verify_environment_pattern]]\n\
         id = \"disk-full\"\n\
         pattern = \"No space left on device\"\n\
         stream = \"both\"\n\
         reason = \"the disk filled. Reclaim something.\"\n"
    } else {
        ""
    };
    // `Fixture … .git().base_commit()` rather than `init_repo`, which
    // initialises and does NOT commit: `land::verify` reads this clone's HEAD
    // before it runs anything, so an unborn HEAD refuses at the boundary and
    // every case here would be asserting over a lap that never reached the gate.
    common::Fixture::at(common::scratch(name).join("repo"))
        .config(&format!("version = 1\n{classifier}"))
        .file("lib.rs", "fine\n")
        .git()
        .base_commit()
        .build()
}

/// Run `batten land verify` in `dir` with the gate configured.
fn verify(dir: &std::path::Path, gate: &str) -> (i32, String) {
    let output = common::batten()
        .arg("land")
        .arg("verify")
        .env("LAND_VERIFY", gate)
        .current_dir(dir)
        .output()
        .expect("the compiled binary runs");
    let mut both = String::from_utf8_lossy(&output.stdout).into_owned();
    both.push_str(&String::from_utf8_lossy(&output.stderr));
    (
        output.status.code().expect("the child exited normally"),
        both,
    )
}

/// **A REFUSAL MATCHING A DECLARED ROW IS THE ENVIRONMENT'S.**
///
/// Measured 2026-08-21: the reclaim passed the lap with 6242MB against its
/// 4096MB floor, the link step consumed all of it, and the stop said *"Reproduce
/// and fix locally"* over a tree with nothing wrong in it.
///
/// The remedy asserted is the ROW'S OWN, which is what proves the engine read it
/// back out rather than composing one — a composed remedy would be this
/// repository's vocabulary inside `crates/batten`.
#[test]
fn a_refusal_the_declared_row_matches_is_named_as_the_environment() {
    let dir = repo("verify-advice-environment", true);
    let gate = failing_gate(
        &dir,
        "'rustc-LLVM ERROR: IO failure: No space left on device'",
    );
    let (code, said) = verify(&dir, &gate);

    assert_eq!(code, 2, "a gate that ran and refused is a verdict");
    assert!(
        said.contains("environment rather than of this tree"),
        "the refusal should be named as the environment's: {said}"
    );
    assert!(
        said.contains("Reclaim something"),
        "the row's own remedy should be read back out: {said}"
    );
    // THE ASSERTION THAT FAILED BEFORE THIS LANDED.
    assert!(
        !said.contains("reproduce and fix locally"),
        "advice for a defect this branch did not write: {said}"
    );
}

/// **ANTI-VACUITY: a refusal matching nothing still gets the ordinary advice.**
///
/// Without this, a classifier that answered *environment* unconditionally would
/// satisfy the case above — and it would be CLOUD-811's defect facing the other
/// way, telling every author with a genuine test failure to check their disk.
#[test]
fn a_refusal_matching_no_declared_row_still_says_reproduce_it_locally() {
    let dir = repo("verify-advice-ordinary", true);
    let gate = failing_gate(&dir, "'tests/primitives.rs:1171 a real finding'");
    let (code, said) = verify(&dir, &gate);

    assert_eq!(code, 2, "{said}");
    assert!(
        said.contains("reproduce and fix locally"),
        "an ordinary refusal keeps the advice that is right for it: {said}"
    );
    assert!(
        !said.contains("environment rather than of this tree"),
        "nothing declared matched, so nothing may be blamed on the machine: {said}"
    );
}

/// **AN UNDECLARED TABLE CLASSIFIES NOTHING, and that is the safe direction.**
///
/// A consumer who declares no rows gets the advice that was always given. The
/// engine must not invent a classifier of its own — the literal is a toolchain's
/// wording and belongs to the repository that runs it (non-negotiable rule 1).
#[test]
fn a_consumer_declaring_no_rows_classifies_nothing_as_the_environment() {
    let dir = repo("verify-advice-undeclared", false);
    let gate = failing_gate(
        &dir,
        "'rustc-LLVM ERROR: IO failure: No space left on device'",
    );
    let (code, said) = verify(&dir, &gate);

    assert_eq!(code, 2, "{said}");
    assert!(
        said.contains("reproduce and fix locally"),
        "with no declared row the ordinary advice stands: {said}"
    );
    assert!(
        !said.contains("environment rather than of this tree"),
        "the engine must carry no classifier of its own: {said}"
    );
}

/// Leave a bet on disk: a `BASE_REF` naming a commit this HEAD is built on.
///
/// `speculation::recover` requires exactly that ancestry — a ref naming a commit
/// the tree is NOT built on is stale rather than stranded, and the two must not
/// be confused. So the fixture commits twice and records the first.
fn leave_a_bet(dir: &std::path::Path) -> String {
    let base = common::git_in(dir, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    std::fs::write(dir.join("more.txt"), "more\n").expect("write a second file");
    common::git_in(dir, &["add", "-A"]);
    common::git_in(dir, &["commit", "-q", "-m", "second"]);
    // `speculation::BASE_REF` spelled through the constant, so a rename moves
    // this fixture with it rather than leaving it recording under a name nothing
    // reads — which would pass the anti-vacuity twin and fail nothing.
    let reference = dir.join(".git").join(batten::speculation::BASE_REF);
    let parent = reference.parent().expect("the ref has a directory");
    std::fs::create_dir_all(parent).expect("create the ref directory");
    std::fs::write(&reference, format!("{base}\n")).expect("record the bet");
    base
}

/// **A REFUSAL OVER A BORROWED TREE SAYS SO, AND SAYS IT AS A SUSPICION.**
///
/// CLOUD-727. Measured 2026-08-19: a two-commit branch touching only memories
/// failed on two findings in files neither commit touched, and rebasing off the
/// speculative base was green first try. On 2026-08-22 the masked failure was in
/// the lander's OWN suite — the most expensive possible wrong place to send
/// someone.
///
/// **The wording is the assertion.** That row retracted two attributions in one
/// day for treating *speculative* as the explanation because it was the salient
/// difference, so the message must say how to FIND OUT rather than deciding: the
/// failure *may not be yours*, and *if it still fails off the borrowed base, it
/// is yours*.
#[test]
fn a_refusal_over_a_borrowed_tree_names_the_base_and_offers_both_recoveries() {
    let dir = repo("verify-advice-speculative", true);
    let base = leave_a_bet(&dir);
    let gate = failing_gate(&dir, "'tests/primitives.rs:1171 a real finding'");
    let (code, said) = verify(&dir, &gate);

    assert_eq!(code, 2, "{said}");
    assert!(
        said.contains("this tree is SPECULATIVE"),
        "a borrowed tree must say so: {said}"
    );
    assert!(
        said.contains(&base[..7]),
        "the borrowed base is the pointer a reader follows: {said}"
    );
    // BOTH recoveries: `rebase --onto` is not the only one, and the cheaper one
    // is available whenever the remote still holds this branch unborrowed.
    assert!(said.contains("rebase --onto"), "{said}");
    assert!(said.contains("reset --hard"), "{said}");
    // A SUSPICION, NEVER A VERDICT.
    assert!(said.contains("may not be yours"), "{said}");
    assert!(
        said.contains("If it still fails off the borrowed base, it is yours"),
        "the message says how to find out rather than deciding: {said}"
    );
    // The advice that is wrong here must not also be present.
    assert!(
        !said.contains("reproduce and fix locally"),
        "pointing at a defect the author did not write: {said}"
    );
}

/// **ANTI-VACUITY: no bet, no borrowed-base advice.**
///
/// The twin that stops the fix widening a message which is already right in the
/// common case. Same failure, same gate, no bet on disk.
#[test]
fn a_refusal_with_no_bet_outstanding_gets_the_ordinary_advice() {
    let dir = repo("verify-advice-unspeculative", true);
    let gate = failing_gate(&dir, "'tests/primitives.rs:1171 a real finding'");
    let (code, said) = verify(&dir, &gate);

    assert_eq!(code, 2, "{said}");
    assert!(said.contains("reproduce and fix locally"), "{said}");
    assert!(
        !said.contains("this tree is SPECULATIVE"),
        "there is no borrowed base to blame: {said}"
    );
}

/// **THE GATE'S OWN OUTPUT REACHES THE OPERATOR.**
///
/// `land::verify` ran through `exec::run_in_env`, whose `ExecConfig::DEFAULT`
/// has `tee: false` — right for `batten exec`, where the bytes are addressable
/// and a caller can go and read them, and wrong for an interactive lap that has
/// just stopped. `Verified`'s own header claimed the output "went to the
/// caller's terminal where it belongs" and it had never done so.
#[test]
fn the_gate_that_refused_is_shown_saying_why() {
    let dir = repo("verify-advice-tee", true);
    let gate = failing_gate(&dir, "'tests/primitives.rs:1171 a real finding'");
    let (_, said) = verify(&dir, &gate);

    assert!(
        said.contains("a real finding"),
        "the operator is shown what the gate said: {said}"
    );
}
