//! `while_marker` over the compiled binary — CLOUD-1390's refusing half.
//!
//! # Why this tier, and what a unit test structurally cannot reach
//!
//! `hook::modifier_admits` is pure over a `Rule` and an `Envelope`, and
//! `src/hook.rs` drives both polarities of the other two modifier columns against
//! fabricated values. It cannot drive this one: the condition is a FILE, under a
//! git dir this process has to resolve, named for a branch this process has to
//! read. A fabricated input cannot vouch for whether the marker the end of a turn
//! writes is the marker the start of the next one finds — and that crossing is the
//! whole mechanism. `tests/claim_receipt.rs` states the same reason for the same
//! surface one column over.
//!
//! # The pair is the point, and one half alone proves nothing
//!
//! `a_write_after_a_punt_is_refused` is satisfied by a row that refuses every
//! write on every branch forever, which is not a gate but an outage.
//! `an_ordinary_turn_leaves_the_next_write_alone` is what rules that out, and it
//! is the case CLOUD-1390 names as the anti-vacuity mirror. Neither is decoration
//! for the other; the two `#MUTANT` rows on `marker_present` kill exactly one
//! each.
//!
//! # No receipt is ever minted here, deliberately
//!
//! Both cases run with the `verify` receipt ABSENT, so the only thing that differs
//! between them is the marker. A case that minted a receipt would be testing
//! `receipt::validity` — which `tests/claim_receipt.rs` already owns — and would
//! let a broken `while_marker` pass by accident whenever the receipt half happened
//! to decide the same way.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::path::{Path, PathBuf};

use common::{Fixture, batten, git_in, run_with_stdin, stderr};

/// The committed row's shape, with nothing else declared.
///
/// Written here rather than read from this repository's own `batten.toml`, on
/// `tests/claim_receipt.rs`'s reason: these cases are about the COLUMN, the
/// committed row is pinned by the census in `tests/cli.rs`, and a fixture that
/// inherited real policy would adjudicate this repo's protected paths too.
const POLICY: &str = r#"version = 1

[[rule]]
id = "turn mint ahead"
kind = "receipt"
scope = "mediated_call"
severity = "deny"
trigger = "write"
while_marker = "unlanded-nudged"
checks = ["verify"]
key = "head"
reason = "run `mise run verify`, then `mise run linear-check`, then `mise run land`"
"#;

/// The branch every case runs on. Carries a `/`, because the marker's filename
/// replaces it and a slug that kept the separator would name a subdirectory that
/// does not exist — a could-not-look the fail-open arm would read as *allow*.
const BRANCH: &str = "claude/cloud-1390-probe";

/// A repository on [`BRANCH`], with the row loaded and no receipt store at all.
fn repo(name: &str) -> PathBuf {
    let dir = Fixture::new(name)
        .config(POLICY)
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    git_in(&dir, &["checkout", "-q", "-b", BRANCH]);
    dir
}

/// Write the marker the way `unlanded_pointer` does: one empty-bodied file under
/// the git dir, named for the family and the branch with separators replaced.
///
/// **The body is not read and this helper writes none on purpose.** `while_marker`
/// asks whether the path exists; a helper that wrote a plausible body would let a
/// reader that parsed one pass here while failing against the real thing, which
/// records only a suppression fingerprint.
fn punt(dir: &Path) {
    let git_dir = git_in(dir, &["rev-parse", "--absolute-git-dir"]);
    let receipts = PathBuf::from(git_dir.trim()).join("batten-receipts");
    std::fs::create_dir_all(&receipts).expect("create the receipt store");
    std::fs::write(
        receipts.join(format!("unlanded-nudged.{}", BRANCH.replace('/', "-"))),
        "",
    )
    .expect("write the marker");
}

fn write_payload(path: &str) -> String {
    let encoded = serde_json::to_string(path).expect("a path is encodable");
    format!(
        "{{\"hook_event_name\":\"PreToolUse\",\"tool_name\":\"Write\",\
         \"tool_input\":{{\"file_path\":{encoded}}}}}"
    )
}

fn verdict(dir: &Path, path: &str) -> Option<i32> {
    run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload(path),
    )
    .status
    .code()
}

#[test]
fn a_write_after_a_punt_is_refused() {
    // THE MEASURED TURN. Four rows built, nothing landed, a status table offered
    // instead — and the next turn wrote files as if nothing had happened. The
    // nudge fired and was reasoned past, twice.
    let dir = repo("punt-deny");
    punt(&dir);
    assert_eq!(
        verdict(&dir, "src/tracked.rs"),
        Some(2),
        "a branch carrying the marker must refuse the next write"
    );
    // A new file is the commonest shape of the first edit after a punt, and
    // exempting untracked paths would leave the hole open where it is widest.
    assert_eq!(verdict(&dir, "src/brand_new.rs"), Some(2));
}

#[test]
fn an_ordinary_turn_leaves_the_next_write_alone() {
    // ANTI-VACUITY, and the half CLOUD-1390 names. Identical repository,
    // identical row, no `verify` receipt either — the ONLY difference is that no
    // marker was written. Without this, a row denying every write on every branch
    // satisfies the case above.
    let dir = repo("punt-allow");
    assert_eq!(
        verdict(&dir, "src/tracked.rs"),
        Some(0),
        "a turn that did not punt owes this row nothing"
    );
}

#[test]
fn the_refusal_names_the_row_and_its_remedy() {
    // Pointer-only (rule 4): the rule id and the route, never the marker's path —
    // a receipt-store path is a fact about this checkout and names the branch.
    let dir = repo("punt-refusal");
    punt(&dir);
    let refusal = stderr(&run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    ));
    assert!(
        refusal.contains("turn mint ahead"),
        "names the rule: {refusal}"
    );
    assert!(
        refusal.contains("verify"),
        "names the check it wants proved: {refusal}"
    );
    // THE PROSE IS NOT ON THIS CHANNEL, and asserting it were would have been
    // this case arguing against the posture its own row follows. `reason` is
    // reached through `batten policy rule`, which is where a remedy belongs
    // (house-style §6, non-negotiable rule 4): the channel carries a pointer and
    // the document carries the payload.
    assert!(
        !refusal.contains("mise run land"),
        "the remedy stays in the config the refusal points at: {refusal}"
    );
    assert!(
        !refusal.contains("batten-receipts"),
        "no store path reaches the channel: {refusal}"
    );
}

/// The wedge, built the way it actually happened: a `verify` receipt minted at
/// one head, then a commit that moves the head past it.
///
/// **Minted by the verb rather than written by hand**, because the receipt is an
/// in-toto statement whose `recorded_git_dir` and config epoch are read from this
/// checkout. A fabricated file would answer [`Validity::Missing`] and the cases
/// below would then be about the wrong class — `receipt read missing`, which has
/// always had a reachable remedy.
fn superseded(name: &str) -> PathBuf {
    let dir = repo(name);
    let recorded = batten()
        .current_dir(&dir)
        .args(["receipt", "record", "verify"])
        .output()
        .expect("run batten receipt record");
    assert!(
        recorded.status.success(),
        "the premise is a receipt that WAS valid: {}",
        stderr(&recorded)
    );
    // The commit is what supersedes it, and it is the ordinary remedial action:
    // AGENTS.md mandates committing early and often, and `key = "head"` makes
    // exactly that void the evidence.
    std::fs::write(dir.join("src/tracked.rs"), "// moved on\n").expect("move the bytes");
    git_in(&dir, &["add", "-A"]);
    git_in(&dir, &["commit", "-q", "-m", "chore: move the head"]);
    punt(&dir);
    dir
}

#[test]
fn a_superseded_receipt_still_refuses_an_unarticulated_write() {
    // ANTI-VACUITY, and it is the half that keeps CLOUD-1823's route from being a
    // password. Declaring an `override` route changes what is AVAILABLE, never
    // what is decided: a caller who has articulated nothing is refused exactly as
    // before, and the class it is refused under is unchanged.
    let dir = superseded("punt-superseded-bare");
    let output = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an unadmitted write over a stale receipt is still refused"
    );
    let said = stderr(&output);
    assert!(
        said.contains("receipt read other"),
        "and under the amend-or-rebase class: {said}"
    );
}

#[test]
fn the_bare_variable_no_longer_clears_a_superseded_receipt() {
    // THE TIGHTENING, and the assertion a reviewer of CLOUD-1823 should look for
    // first. `hook::Policy::honours_hatch` stops honouring `BATTEN_HOOK_BYPASS`
    // for any class declaring an `override` route with a precondition, so
    // DECLARING the route is what takes the password away. Before it, this exact
    // call exited 0 — measured on this repository's own wedged branch, where the
    // variable was the only exit that existed.
    //
    // Pinned here rather than left to `hook.rs`'s unit tier because the unit tier
    // fabricates a registry, and what this asserts is that the VENDORED registry
    // the binary ships carries the route.
    let dir = superseded("punt-superseded-hatch");
    let mut command = batten();
    command
        .current_dir(&dir)
        .args(["adjudicate", "--harness", "exit-code"])
        .env(batten::hook::BYPASS_ENV, "1")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().expect("spawn the bypassed adjudication");
    {
        use std::io::Write as _;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(write_payload("src/tracked.rs").as_bytes())
            .expect("write the payload");
    }
    let output = child.wait_with_output().expect("collect the verdict");
    assert_eq!(
        output.status.code(),
        Some(2),
        "the bare variable must not open a class that declares an articulation route: {}",
        stderr(&output)
    );
}

#[test]
fn the_class_declares_the_route_that_makes_the_wedge_escapable() {
    // CLOUD-1823's own predicate, asked of the registry rather than of a refusal.
    //
    // The wedge was not that the refusal was wrong — it was that the ONLY declared
    // remedy, re-running the named check, cannot change its answer when that check
    // is red for reasons only a write repairs, and the write is what is refused.
    // An `override` route carrying a precondition is what `admission::questions_for`
    // reads, so its presence IS the exit existing.
    let entry = batten::verdict::vendored()
        .into_iter()
        .find(|entry| entry.id == "receipt read other")
        .expect("the class is vendored");
    assert!(
        entry
            .routes
            .iter()
            .any(|route| route.kind == batten::verdict::RouteKind::Override
                && route.precondition.is_some()),
        "the class must declare an articulation route, or the wedge returns"
    );
}

#[test]
fn a_marker_no_sweep_clears_is_refused_at_load() {
    // THE SPEND IS WHAT MAKES THE REFUSAL FINITE. A `while_marker` naming a family
    // `retire_branch` does not sweep would deny past its own landing and on into
    // the next piece of work to reuse the branch name — CLOUD-774's inherited
    // suppression, in the refusing direction. `Rule::validate_marker` refuses the
    // row rather than shipping a deny nothing can clear.
    let dir = Fixture::new("punt-unswept")
        .config(&POLICY.replace(
            "while_marker = \"unlanded-nudged\"",
            "while_marker = \"never-swept\"",
        ))
        .file("src/tracked.rs", "// committed\n")
        .git()
        .base_commit()
        .build();
    let output = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    );
    let said = stderr(&output);
    assert_eq!(
        output.status.code(),
        Some(1),
        "a config that cannot be loaded is a usage error, never a verdict: {said}"
    );
    assert!(said.contains("never-swept"), "names the marker: {said}");
    assert!(
        said.contains("unlanded-nudged"),
        "names what it could have said instead: {said}"
    );
}
