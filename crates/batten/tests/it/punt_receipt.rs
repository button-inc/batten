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
    // reads, so its presence is NECESSARY for the exit to exist.
    //
    // **AND NOT SUFFICIENT, WHICH THIS CASE USED TO CLAIM** (CLOUD-1880). The
    // sentence above ended "so its presence IS the exit existing", and that
    // inference is a membership check standing in for a predicate — the exact
    // substitution this repository's own rules name. It was false for the whole of
    // CLOUD-1823's life: the route was declared, this case was green, and spending
    // the route did not admit the write, because a receipt refusal named no
    // subject for the admission to bind to.
    //
    // `a_spent_admission_clears_a_superseded_receipt` is the sufficiency half and
    // the two must travel together. This one stays because it localises the
    // failure: green here and red there says the registry is fine and the boundary
    // is not, which is a different repair from the route having been dropped.
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

/// The three answers `override request` asks of `receipt read other`, one
/// `<id>=<text>` line each, on stdin — the spelling `run-shape` blesses.
const ANSWERS: &str = "precondition=verify is red on this head for a reason only a write repairs\n\
                       lost=the write that repairs it cannot be made\n\
                       rejected-route=re-running verify cannot change its answer on this head\n";

/// Run a `batten override` verb for the superseded receipt's own situation.
///
/// The subject is READ OFF THE REFUSAL, the only spelling an agent has: the
/// artifacts it renders between the verdict and the rule, comma-joined. A receipt
/// refusal names no path, so it binds every artifact it names (CLOUD-1871) — which
/// is also what keeps an admission taken for one situation from covering another.
fn override_verb(dir: &Path, verb: &[&str], stdin: &str) -> std::process::Output {
    let refused = run_with_stdin(
        dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&refused.stdout),
        stderr(&refused)
    );
    let subject = said
        .lines()
        .find_map(|line| {
            let rest = line.split("receipt read other ").nth(1)?;
            let artifacts = rest.split(" turn mint ahead").next()?;
            Some(artifacts.split_whitespace().collect::<Vec<_>>().join(","))
        })
        .unwrap_or_else(|| panic!("the write is refused as `receipt read other`: {said}"));
    let mut args = vec!["override"];
    args.extend_from_slice(verb);
    args.extend_from_slice(&[
        "--rule",
        "turn mint ahead",
        "--verdict",
        "receipt read other",
        "--subject",
        &subject,
    ]);
    run_with_stdin(dir, &args, stdin)
}

// CLOUD-1889's declared mutation, and why the row is in THIS file.
//
// `test name undefined` reads the declared file for a line carrying
// `MUTANT <slug>|`, and its `line_sources` cover `crates/batten/tests/**` and not
// `crates/batten/src/**` — so the row lives here although the expression it applies
// belongs to `lib.rs`'s `admit_mediated`. It reinstates the early return on a
// path-less refusal, which is the defect exactly.
//
// INERT UNDER THE SWEEP, as `rebase.rs` records for its own rows (CLOUD-1486):
// `mutate::apply` seds the file that DECLARED the row, so this row rewrites this
// file and never reaches the engine. The kill was demonstrated BY HAND at
// implementation — the expression applied to `lib.rs`, the case below observed
// red, the file restored — and this paragraph is the only record of it.
/*
#MUTANT-SUITE crates/batten/tests/it/punt_receipt.rs
#MUTANT admission-not-honoured|s@    let subject = refusal.subject().unwrap_or(class);@    let Some(subject) = refusal.subject() else { return Ok(decision); };@|a_spent_admission_clears_a_superseded_receipt
*/

#[test]
fn a_spent_admission_clears_a_superseded_receipt() {
    // CLOUD-1889 — the half this file never had. The three cases above prove the
    // route is DECLARED, that an unarticulated write is still refused, and that the
    // bare variable stopped working. None of them proved the route could be TAKEN,
    // and it could not: `admit_mediated` returned early on a refusal with no path
    // subject, which is every receipt refusal, so `spend` reported "spent" and the
    // write was refused identically. That is how the dead branch landed green.
    let dir = superseded("punt-superseded-admitted");

    let requested = override_verb(&dir, &["request"], ANSWERS);
    assert!(
        requested.status.success(),
        "the class declares an articulation route, so a request answering it is issued: {}",
        stderr(&requested)
    );
    let admission = String::from_utf8(requested.stdout)
        .expect("stdout is UTF-8")
        .trim()
        .to_owned();
    assert!(
        !admission.is_empty(),
        "the request prints its admission address"
    );

    let spent = override_verb(&dir, &["spend", "--admission", &admission], "");
    assert!(
        spent.status.success(),
        "the admission spends: {}",
        stderr(&spent)
    );

    let output = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    );
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        stderr(&output)
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "a spent admission clears the write it was issued for: {said}"
    );
    // POINTER, NEVER THE ANSWERS (rule 4): the run names which record admitted the
    // call, so the suppression is auditable rather than the silent bypass again.
    assert!(
        said.contains(&admission),
        "the admitting record is named: {said}"
    );
    assert!(
        !said.contains("re-running verify"),
        "the articulation stays in the store: {said}"
    );
}

/// Request an admission for `dir`'s superseded receipt and return its address.
fn issued(dir: &Path) -> String {
    let requested = override_verb(dir, &["request"], ANSWERS);
    assert!(
        requested.status.success(),
        "the request is issued: {}",
        stderr(&requested)
    );
    String::from_utf8(requested.stdout)
        .expect("stdout is UTF-8")
        .trim()
        .to_owned()
}

/// ISSUED IS NOT SPENT (CLOUD-1889's second case). Articulating costs the
/// thinking and spending is what consumes it; `admission::admitted` reads
/// `State::Spent` alone. An issued record that suppressed on its own would be
/// the retired password again: hold the address, pay nothing, pass forever.
#[test]
fn an_issued_admission_that_was_never_spent_clears_nothing() {
    let dir = superseded("punt-superseded-issued");
    let _unspent = issued(&dir);
    let output = run_with_stdin(
        &dir,
        &["adjudicate", "--harness", "exit-code"],
        &write_payload("src/tracked.rs"),
    );
    assert_eq!(
        output.status.code(),
        Some(2),
        "an issued, unspent admission admits nothing: {}",
        stderr(&output)
    );
}

/// A COMMIT UNBINDS IT (CLOUD-1889's third case), deliberately. The anchor is
/// the head the admission was spent at, which is what the receipt is keyed to,
/// so the next commit is a new situation and costs its own articulation.
///
/// Measured before it was pinned, on the branch that carried this case: an
/// admission spent at one head stopped clearing writes the moment the next
/// commit landed. This makes that a contract rather than an observation.
#[test]
fn an_admission_spent_one_commit_ago_clears_nothing() {
    let dir = superseded("punt-superseded-stale");
    let payload = write_payload("src/tracked.rs");
    let admission = issued(&dir);
    let spent = override_verb(&dir, &["spend", "--admission", &admission], "");
    assert!(spent.status.success(), "{}", stderr(&spent));
    assert_eq!(
        run_with_stdin(&dir, &["adjudicate", "--harness", "exit-code"], &payload)
            .status
            .code(),
        Some(0),
        "the premise: at its own head the admission clears the write"
    );

    std::fs::write(dir.join("src/tracked.rs"), "// and on again\n").expect("move the bytes");
    git_in(&dir, &["add", "-A"]);
    git_in(
        &dir,
        &["commit", "-q", "-m", "chore: move the head once more"],
    );

    let output = run_with_stdin(&dir, &["adjudicate", "--harness", "exit-code"], &payload);
    assert_eq!(
        output.status.code(),
        Some(2),
        "an admission spent at the previous head does not clear this one: {}",
        stderr(&output)
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
