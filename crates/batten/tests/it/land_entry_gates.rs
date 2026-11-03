//! The landing's entry gates and the retirement of a landed branch
//! (CLOUD-1471), over the compiled binary and the library.
//!
//! # Why these two are one file
//!
//! They are the two clusters `mise-tasks/land.sh` carried that no successor
//! did — its first act and its last. Neither is a step of the lap, so neither
//! landed with the pipeline; both would have gone on the floor with the program.
//! Keeping them together is what makes that pairing legible to the next reader.
//!
//! # The entry gate is driven end to end, and it can be
//!
//! It runs before the lease, the singleton and any spend, so `land lap` reaches
//! it with no forge state to fabricate beyond the pull request lookup — which is
//! `rest`'s fixture seam. A refusal there is the whole assertion: the lap stops
//! at exit 2 having spent nothing.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

const REPO: &str = "acme/widgets";
const PR: &str = "42";

/// One open pull request, in the response shape the fixture reads.
fn one_pull_request() -> String {
    format!("HTTP/2 200\ncontent-type: application/json\n\n[{{\"number\":{PR}}}]\n")
}

/// A repository on a branch, with the pull-request lookup canned.
fn fixture(name: &str) -> std::path::PathBuf {
    let dir = common::scratch(name);
    common::init_repo(&dir);
    // A REMOTE THAT RESOLVES AND CANNOT BE REACHED, which is exactly the state
    // these cases need. `land lap` resolves `origin` before the first step, so
    // without one it stops with "no base" and the entry gate is never reached;
    // and every case here asserts that the gate stops the lap BEFORE it fetches,
    // so a remote that would answer is the wrong fixture — a case reaching the
    // fetch has already failed its own claim.
    common::git_in(&dir, &["remote", "add", "origin", "file:///nonexistent"]);
    // NO TRACKING REF IS PINNED, and the absence is the assertion's other half:
    // every case here claims the entry gate stops the lap before it looks at the
    // base at all, so a fixture that supplied one would let a case pass over a
    // gate asked too late.
    common::git_in(&dir, &["checkout", "-q", "-b", "topic"]);
    std::fs::write(dir.join("resp.last"), one_pull_request()).expect("write the canned answer");
    let module = std::fs::read_to_string(common::at_root(MODULE)).expect("the module");
    common::write(&dir, MODULE, &module);
    dir
}

/// The committed decision module the fixture registers.
const MODULE: &str = "policy/pr-unsubscribed.rego";

/// The session variable the fixture's `[lease.unsubscribed]` names — not the
/// harness's own, so a case never reads the session it runs in.
const SESSION_ENV: &str = "LAND_ENTRY_FIXTURE_SESSION";

/// The fixture's config: the module, its verdicts, and `lease` as the
/// `[lease.unsubscribed]` table's body (empty declares no entry gate).
fn config(dir: &std::path::Path, lease: &str) {
    let table = if lease.is_empty() {
        String::new()
    } else {
        format!("\n[lease.unsubscribed]\n{lease}")
    };
    common::write(
        dir,
        "batten.toml",
        &format!(
            r#"version = 1
scope = ["**"]

[[verdict]]
id = "event watch held"
gloss = "no receipt"
class = "fixture"

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run pr-unsubscribed drop"

[[verdict]]
id = "event read partial"
gloss = "torn"
class = "fixture"

[[verdict.route]]
id = "task run first"
kind = "command"
target = "mise run pr-unsubscribed check"

[[rule]]
id = "event watch other"
kind = "policy"
scope = "tree"
module = "{MODULE}"
severity = "deny"

[[record]]
record = "pr-unsubscribed"
writer = "mise run pr-unsubscribed check"
{table}"#
        ),
    );
}

/// The entry gate this repository declares, over the fixture's session
/// variable. No credential is declared, so the advisory drop always gives up.
fn declared() -> String {
    format!(
        "session_env = \"{SESSION_ENV}\"\nfamily = \"pr-unsubscribed\"\nrule = \"event watch other\"\n"
    )
}

/// Run `batten land lap` against the fixture, in `session` when one is given.
fn lap(dir: &std::path::Path, session: Option<&str>) -> (i32, String, String) {
    let mut command = common::batten();
    command
        .arg("land")
        .arg("lap")
        .arg("main")
        .env("GH_REPO", REPO)
        .env("BATTEN_REST_FIXTURE", dir)
        // Bounded so a lap that gets PAST the entry gate cannot run away: every
        // case here is about the gate, and a runaway would be reported as a hang
        // rather than as the miss it is.
        .env("LAND_MAX_LAPS", "1")
        .current_dir(dir);
    match session {
        Some(session) => command.env(SESSION_ENV, session),
        None => command.env_remove(SESSION_ENV),
    };
    let output = command.output().expect("the compiled binary runs");
    (
        output.status.code().expect("the child exited normally"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// **A SESSION THAT NEVER DROPPED ITS SUBSCRIPTION IS REFUSED BEFORE ANYTHING IS
/// SPENT, over THIS pull request** (CLOUD-2387).
///
/// The number is the ENGINE's, resolved from the branch and handed to the
/// reading: the rule's own words name `#42`, which is the lookup's answer and
/// nothing the config spelled.
#[test]
fn a_session_that_never_unsubscribed_stops_the_landing_over_this_pull_request() {
    let dir = fixture("land-entry-refuses");
    config(&dir, &declared());
    let (code, _, err) = lap(&dir, Some("cse_fixture"));

    assert_eq!(
        code, 2,
        "the refusal is a verdict about this landing: {err}"
    );
    assert!(err.contains("refused this landing"), "stderr: {err}");
    // THE RULE'S OWN WORDS REACH THE OPERATOR (CLOUD-407).
    assert!(err.contains(&format!("#{PR}")), "stderr: {err}");
}

/// **THE DROP IS ADVISORY: one that cannot run does not stop a landing whose
/// session already holds its receipt.**
///
/// No credential is declared, so the drop gives up on every case here; the
/// mirror is the case above, where the same give-up and no receipt refuses.
#[test]
fn a_held_receipt_clears_the_gate_though_the_drop_could_not_run() {
    let dir = fixture("land-entry-receipt");
    config(&dir, &declared());
    let store = dir.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&store).expect("create the receipt store");
    std::fs::write(
        store.join(format!("pr-unsubscribed.cse_fixture.{PR}")),
        "pr 42\n",
    )
    .expect("write the receipt");
    let (code, out, err) = lap(&dir, Some("cse_fixture"));

    assert!(
        out.contains("entry gate `event watch other` is clear"),
        "stdout: {out}\nstderr: {err}"
    );
    assert!(!err.contains("refused this landing"), "stderr: {err}");
    assert_ne!(code, 2, "a held receipt must not refuse: {err}");
}

/// **AN UNDECLARED ENTRY GATE IS A PASS**: naming none is a legitimate
/// configuration, and the lap goes on without asking anything.
#[test]
fn an_undeclared_entry_gate_asks_nothing() {
    let dir = fixture("land-entry-undeclared");
    config(&dir, "");
    let (_, out, err) = lap(&dir, Some("cse_fixture"));

    assert!(!out.contains("entry gate"), "stdout: {out}");
    assert!(!err.contains("entry gate"), "stderr: {err}");
}

/// **A CONFIG THAT WILL NOT LOAD IS NOT ONE DECLARING NO GATE** (code review of
/// #1248). Read as "no `[lease.unsubscribed]`", it took the undeclared-is-a-pass
/// arm and the landing went ahead unasked; it is a could-not-look, so `3`.
#[test]
fn a_config_that_will_not_load_refuses_rather_than_skipping_the_entry_gate() {
    let dir = fixture("land-entry-broken-config");
    common::write(&dir, "batten.toml", "this is not = = toml\n");
    let (code, _, err) = lap(&dir, Some("cse_fixture"));

    assert_eq!(code, 3, "stderr: {err}");
    assert!(err.contains("will not load"), "stderr: {err}");
}

/// **A DECLARED GATE THAT CANNOT BE DECIDED IS A REFUSAL, NOT A PASS.**
///
/// The dead-gate class this engine exists to refuse. `3` rather than `2` —
/// nothing was decided about the repository.
#[test]
fn a_declared_entry_gate_that_will_not_run_is_refused() {
    let dir = fixture("land-entry-unrunnable");
    config(
        &dir,
        &format!(
            "session_env = \"{SESSION_ENV}\"\nfamily = \"pr-unsubscribed\"\nrule = \"no such rule\"\n"
        ),
    );
    let (code, _, err) = lap(&dir, Some("cse_fixture"));

    assert_eq!(
        code, 3,
        "an unasked precondition is a could-not-look: {err}"
    );
    assert!(err.contains("unasked rather than met"), "stderr: {err}");
}

/// **A DECLARED GATE OVER A PULL REQUEST NOBODY CAN NAME IS REFUSED, and this is
/// the one read in the family that does NOT fail open.**
///
/// Everywhere else could-not-look carries on, because spending nothing is the
/// safe direction for a question about CI. Here carrying on is exactly the dead
/// gate: the precondition was declared and never asked.
#[test]
fn entry_gates_over_an_unresolvable_pull_request_are_refused() {
    let dir = fixture("land-entry-no-pr");
    config(&dir, &declared());
    // An empty list: the lookup succeeds and names nothing, which is the shape a
    // branch with no open pull request produces.
    std::fs::write(
        dir.join("resp.last"),
        "HTTP/2 200\ncontent-type: application/json\n\n[]\n",
    )
    .expect("write the canned answer");
    let (code, _, err) = lap(&dir, Some("cse_fixture"));

    assert_eq!(code, 3, "stderr: {err}");
    assert!(err.contains("cannot be asked"), "stderr: {err}");
}

/// **THE BRANCH-KEYED RECEIPTS GO WITH THE BRANCH (CLOUD-774), and the third
/// family is the one a literal port would have missed.**
///
/// The predecessor swept two stores by name. `Suppression::PerSet` writes a third
/// under the same key shape and landed after that cleanup was written, so a copy
/// of the two literals would leave one family accumulating forever — which is
/// what a named list in the engine exists to stop.
///
/// The remote half is not driven here: `retire_branch` reaches a remote, and this
/// case is about the sweep. It is stated rather than left implied — a reader
/// should not take this file as evidence that the delete or the tracking-ref
/// prune is covered.
#[test]
fn retiring_a_landed_branch_drops_every_branch_keyed_receipt() {
    let dir = common::scratch("land-retire-receipts");
    common::init_repo(&dir);
    let store = dir.join(".git").join("batten-receipts");
    std::fs::create_dir_all(&store).expect("create the receipt store");

    // A branch whose name carries the separator the store flattens, because a
    // sweep spelling the slug differently would delete nothing and report a clean
    // count — the silent-empty-answer shape, one layer down.
    let branch = "claude/some-work";
    // `unlanded-nudged` is the fourth and was missing from the sweep (CLOUD-1390).
    // It is the one whose survival costs most: the nudge is once-per-claim
    // because the agent cannot clear `¬landed` inside the turn it is asked to, so
    // the file exists precisely on branches that stopped with work unlanded —
    // and a reused branch name would inherit the suppression, silencing the one
    // nudge that says the work exists nowhere but here.
    let families = [
        "board-writes",
        "filed-here-nudged",
        "filed-set-nudged",
        "unlanded-nudged",
    ];
    for family in families {
        std::fs::write(store.join(format!("{family}.claude-some-work")), "x\n")
            .expect("write a receipt");
    }
    // One store this sweep must NOT touch: a sha-keyed receipt dies with its sha
    // and belongs to no branch. Without it, a sweep that removed the whole
    // directory would pass.
    std::fs::write(store.join("verify.deadbeef"), "x\n").expect("write a sha-keyed receipt");

    let retired = batten::land::retire_branch(&dir, "file:///nonexistent", branch);

    assert_eq!(retired.receipts, families.len());
    for family in families {
        assert!(
            !store.join(format!("{family}.claude-some-work")).exists(),
            "{family} should have gone with the branch"
        );
    }
    assert!(
        store.join("verify.deadbeef").exists(),
        "a sha-keyed receipt belongs to no branch and must survive"
    );
}
