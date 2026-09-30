//! `batten checks green` decides over the compiled binary (CLOUD-1143).
//!
//! # Why this tier
//!
//! `checks_green.rs`'s own unit cases pin the DECISION. They cannot pin the two
//! things a caller actually branches on, because neither exists until there is a
//! process: the **exit code** each verdict maps to, and whether the red / not-yet
//! distinction survives to stdout. Both are acceptance clauses on the row, and
//! both are invisible to a test that calls `decide` directly.
//!
//! # The property that matters most here
//!
//! `every_non_green_state_exits_non_zero`. The shell this replaces used four
//! distinct codes; `exit.rs` is total over four that mean something else, so the
//! mapping had to change and the safety property had to be restated as something
//! a test can hold. A reader that branches on the code alone and ignores stdout
//! must HOLD on every state that is not green — otherwise the port re-introduces
//! CLOUD-337, where `land` fast-forwarded into a branch protection still listing
//! six checks as expected.
//!
//! That is why red and pending share `Violation` rather than getting a code
//! each: the distinction is real but it is about whether to ask again, and it
//! travels on stdout where the poller reads it.

// THE FILE-GRANULARITY RETIREMENT ARMS (CLOUD-1059). Two paths die, so two arms:
// a program and its suite are separate subjects and one arm covering both would
// claim a conservation nobody checked. Their grammar is disjoint from the case
// arms below by construction — a case arm's first field after the marker is a
// QUOTED case name, a file arm's is a path.
//
// carried: mise-tasks/checks-green.sh crates/batten/src/checks_green.rs kind:verb crates/batten/tests/it/checks_green.rs
// carried: tests/checks-green.bats crates/batten/src/checks_green.rs kind:verb crates/batten/tests/it/checks_green.rs
//
// CLOUD-908's case arms: every `@test` the retired suite declared, and where its
// predicate lives now. Twenty-eight carried and two changed — both changes are
// stated rather than smuggled, because a suite that asserted its own INPUT SEAM
// cannot port to a verb that no longer has that seam.
//
// carried: "a graded, all-success required set is green" crates/batten/src/checks_green.rs kind:verb
// carried: "a partial set on a fresh SHA is not an answer (CLOUD-337)" crates/batten/src/checks_green.rs kind:verb
// carried: "a failure outranks a name that has not registered (CLOUD-337)" crates/batten/src/checks_green.rs kind:verb
// carried: "an all-skipped required set is not an answer" crates/batten/src/checks_green.rs kind:verb
// carried: "a cancelled required check is not an answer either, and says which word" crates/batten/src/checks_green.rs kind:verb
// carried: "one cancelled required check is not redeemed by another that succeeded" crates/batten/src/checks_green.rs kind:verb
// carried: "a fan-in failing over cancelled upstreams is no verdict, not a red one" crates/batten/src/checks_green.rs kind:verb
// carried: "CLOUD-900: a NON-fan-in failure over cancelled siblings IS the verdict" crates/batten/src/checks_green.rs kind:verb
// carried: "CLOUD-900: a non-fan-in failure answers while its siblings are still running" crates/batten/src/checks_green.rs kind:verb
// carried: "CLOUD-900: the fan-in's own failure still yields to the pending bucket" crates/batten/src/checks_green.rs kind:verb
// carried: "CLOUD-900: with no fan-in named, the ordering is CLOUD-363's exactly" crates/batten/src/checks_green.rs kind:verb
// carried: "third-party successes do not make a draft-era skip set an answer" crates/batten/src/checks_green.rs kind:verb
// carried: "a required check still pending is not an answer" crates/batten/src/checks_green.rs kind:verb
// carried: "checks-green.bats::a required check that failed is red, and named" crates/batten/src/checks_green.rs kind:verb
// carried: "a third-party check gets neither a vote nor a veto" crates/batten/src/checks_green.rs kind:verb
// carried: "an absent path-filtered check is not a skipped one (CLOUD-327)" crates/batten/src/checks_green.rs kind:verb
// carried: "CLOUD-376: AN UNKNOWN CONCLUSION HOLDS THE POLL OPEN — it is not red" crates/batten/src/checks_green.rs kind:verb
// carried: "CLOUD-376: a known bad conclusion is still red — the anti-vacuity half" crates/batten/src/checks_green.rs kind:verb
// carried: "a skip superseded by a success is green — the residue does not veto the verdict" crates/batten/src/checks_green.rs kind:verb
// carried: "a skip superseded by a FAILURE is red — the case that made this urgent" crates/batten/src/checks_green.rs kind:verb
// carried: "a success superseded by a skip is NOT an answer — the draft economy survives" crates/batten/src/checks_green.rs kind:verb
// carried: "the id breaks a tie between two runs started in the same second" crates/batten/src/checks_green.rs kind:verb
// carried: "a pending re-run supersedes a completed one — the answer is not in yet" crates/batten/src/checks_green.rs kind:verb
// carried: "each name is judged on its own latest, never one name's run against another's" crates/batten/src/checks_green.rs kind:verb
// carried: "a reading with no ordering key answers as the union did — fail closed" crates/batten/src/checks_green.rs kind:verb
// carried: "PRESSURE: a name with THREE runs on one SHA is judged by its latest" crates/batten/src/checks_green.rs kind:verb
// carried: "PRESSURE: three runs whose LATEST is red is still red" crates/batten/src/checks_green.rs kind:verb
// carried: "an empty reading is not an answer, and takes no network to say so" crates/batten/src/checks_green.rs kind:verb
//
// changed: "checks-green.bats::an unset required set is fatal rather than an empty one" crates/batten/src/checks_green.rs kind:verb the suite asserted an UNSET ENVIRONMENT VARIABLE was fatal, and the verb has no such variable to leave unset — the roster arrives as a flag, so the caller keeps its own authority for where it is written down and the core holds no consumer's name (rule 1, CLOUD-772). The property survives as `an_empty_roster_is_a_usage_error_and_never_green`, which asserts the thing that actually mattered: an empty roster is refused rather than making every check unrequired
// changed: "CLOUD-376: an unset ANSWERED set is fatal for the same reason" crates/batten/src/checks_green.rs kind:verb the same seam change, for the same reason. It survives as `an_empty_answered_set_is_a_usage_error_and_never_green`, and the compiled tier adds the half a unit case cannot reach — that an unusable roster exits Usage rather than the policy verdict, so a config error is never mistaken for an ordinary refusal a caller retries past

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::io::Write;
use std::process::Stdio;

/// The roster this repository actually declares, reduced to what these cases
/// need. Passed as flags rather than read from the environment, which is the
/// whole seam change: the crate holds no consumer's variable name.
const REQUIRED: &str = "ci,perf,final";
const ANSWERED: &str = "success,neutral,failure,timed_out,action_required";

/// Run `batten checks green` with a reading on stdin.
///
/// Spawned rather than routed through `common::run`, because the subject here is
/// what the process does with a PIPE — a helper that passes no stdin would test
/// the empty-reading path five times over and call it coverage.
fn green(reading: &str, args: &[&str]) -> (i32, String, String) {
    let mut child = common::batten()
        .arg("checks")
        .arg("green")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the compiled binary runs");
    child
        .stdin
        .as_mut()
        .expect("stdin is piped")
        .write_all(reading.as_bytes())
        .expect("the reading reaches the child");
    let output = child.wait_with_output().expect("the child answers");
    (
        output.status.code().expect("the child exited normally"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The roster flags every case shares.
fn roster() -> Vec<&'static str> {
    vec![
        "--required",
        REQUIRED,
        "--answered",
        ANSWERED,
        "--fanin",
        "final",
    ]
}

/// A reading in which every required name is terminal and green.
fn all_green() -> String {
    ["ci", "perf", "final"]
        .iter()
        .enumerate()
        .map(|(i, name)| {
            format!(
                "completed\tsuccess\t{name}\t2026-08-12T00:00:00Z\t{}",
                i + 1
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---------------------------------------------------------------------------
// The exit contract, which is the whole reason this file exists.
// ---------------------------------------------------------------------------

#[test]
fn a_green_head_exits_success() {
    let (code, stdout, _) = green(&all_green(), &roster());
    assert_eq!(code, 0, "a green head is the only zero: {stdout}");
    assert!(stdout.contains("terminal and green"), "{stdout}");
}

#[test]
fn every_non_green_state_exits_non_zero() {
    // THE SAFETY PROPERTY, and it is asserted over the states rather than over
    // one of them: a reader that ignores stdout must hold on all five. Under any
    // mapping that gave one of these a `0`, `land` would fast-forward a head
    // nothing had judged — CLOUD-337, re-introduced by the port meant to
    // preserve it.
    //
    // THE FIFTH IS CLOUD-497'S, and it is the one a new arm is likeliest to get
    // wrong: a dead end exits `3`, which is the code a reading that could not be
    // TAKEN also carries, and `3` is a long way from `0` in every direction but
    // the one that matters here. Swept with the rest so the safety property is
    // total over the states rather than over the ones that existed first.
    let cases: [(&str, &str); 5] = [
        ("a required check failed", "completed\tfailure\tci\t\t0"),
        ("a draft-era skip", "completed\tskipped\tci\t\t0"),
        ("a run still going", "in_progress\t-\tci\t\t0"),
        ("nothing registered yet", ""),
        (
            "a closed set with a masked name",
            "completed\tskipped\tci\t\t1\ncompleted\tsuccess\tperf\t\t2\ncompleted\tsuccess\tfinal\t\t3",
        ),
    ];
    for (what, reading) in cases {
        let (code, stdout, _) = green(reading, &roster());
        assert_ne!(code, 0, "{what} must not read as green: {stdout}");
    }
}

#[test]
fn red_and_pending_share_a_code_and_differ_on_stdout() {
    // The distinction the shared code deliberately drops has to survive
    // somewhere, or the poller cannot tell "ask again" from "stop" and either
    // wedges or gives up early. Both halves are asserted, because a port that
    // collapsed them entirely would pass the exit-code case above.
    let (red_code, red_out, _) = green("completed\tfailure\tci\t\t0", &roster());
    let (pending_code, pending_out, _) = green("completed\tskipped\tci\t\t0", &roster());
    assert_eq!(red_code, pending_code, "both are the same policy verdict");
    assert!(red_out.contains("red"), "{red_out}");
    assert!(pending_out.contains("pending"), "{pending_out}");
    assert_ne!(red_out, pending_out);
}

#[test]
fn an_unusable_roster_is_a_usage_error_and_not_the_policy_verdict() {
    // A statement about the INVOCATION, never about the repository. Distinct
    // from the verdict code on purpose: an empty roster makes every check
    // unrequired, and reporting that as "not green" would hide a config error
    // inside an ordinary refusal the caller retries past.
    let (code, _, stderr) = green(&all_green(), &["--required", "", "--answered", ANSWERED]);
    assert_eq!(code, 1, "an empty roster is usage: {stderr}");
    assert!(
        stderr.contains("every check would be unrequired"),
        "{stderr}"
    );
}

// ---------------------------------------------------------------------------
// The rules the port had to conserve, over the real boundary.
// ---------------------------------------------------------------------------

#[test]
fn a_later_run_supersedes_a_drafts_skip_residue() {
    // CLOUD-436 through the PARSER, which the unit case cannot reach: the
    // ordering key arrives as two TSV fields and the id as text, so a reading
    // whose tie-break did not survive parsing would judge the union and veto a
    // verdict that already exists.
    let residue: Vec<String> = ["ci", "perf", "final"]
        .iter()
        .map(|name| format!("completed\tskipped\t{name}\t2026-08-11T00:00:00Z\t1"))
        .collect();
    let reading = format!("{}\n{}", all_green(), residue.join("\n"));
    let (code, stdout, _) = green(&reading, &roster());
    assert_eq!(code, 0, "the newer success speaks for the name: {stdout}");
}

#[test]
fn a_three_field_reading_still_answers() {
    // The predecessor's readings predate the ordering key, and answering one
    // exactly as it did then is itself a property. A parser that required five
    // fields would drop every row and report "nothing registered" — green's
    // opposite, but wrong for the wrong reason.
    let (code, stdout, _) = green("completed\tfailure\tci", &roster());
    assert_eq!(code, 2, "a three-field row is still read: {stdout}");
    assert!(stdout.contains("ci failure"), "{stdout}");
}

#[test]
fn a_tolerated_absence_is_elided_and_a_real_one_is_not() {
    // CLOUD-337 in both directions at once. `zizmor` is path-filtered and
    // produces no run at all, so requiring it would hang; `perf` not having
    // registered yet is a fresh SHA and must hold the poll open.
    let (code, stdout, _) = green(
        "completed\tsuccess\tci\t\t0",
        &[
            "--required",
            "ci,perf,zizmor",
            "--answered",
            ANSWERED,
            "--absent-ok",
            "zizmor",
        ],
    );
    assert_eq!(code, 2);
    assert!(
        stdout.contains("perf"),
        "the unregistered name is named: {stdout}"
    );
    assert!(
        !stdout.contains("zizmor"),
        "the tolerated one is elided: {stdout}"
    );
}

#[test]
fn a_non_fanin_failure_over_cancelled_siblings_is_the_verdict() {
    // CLOUD-900, the case `abandon-matrix` deliberately creates: one real
    // failure beside siblings this repository stopped on purpose. Under
    // CLOUD-363's ordering alone that reads as "not an answer", so the saving
    // would buy a wedge.
    let reading = "completed\tfailure\tci\t\t0\ncompleted\tcancelled\tperf\t\t0\ncompleted\tcancelled\tfinal\t\t0";
    let (code, stdout, _) = green(reading, &roster());
    assert_eq!(code, 2);
    assert!(stdout.contains("red"), "{stdout}");
    assert!(stdout.contains("ci failure"), "{stdout}");
}

#[test]
fn an_unnamed_fanin_leaves_every_failure_manufacturable() {
    // The safe default, and the half easiest to lose in a port: with no fan-in
    // named this is CLOUD-363's ordering intact, so the same reading does not
    // promote a failure that a cancellation may have manufactured.
    //
    // `3` AND "dead-end" SINCE CLOUD-497, and what this case pins is unchanged.
    // Every name here is terminal and none is unregistered, so the reading is
    // closed — it was the wedge itself before the split, a set that said "ask
    // again" to a question nothing would answer. The property asserted is still
    // that no failure is promoted to red; only the spelling of the non-answer
    // moved, and it moved in the direction that stops the poll.
    let reading = "completed\tfailure\tci\t\t0\ncompleted\tcancelled\tperf\t\t0\ncompleted\tcancelled\tfinal\t\t0";
    let (code, stdout, _) = green(reading, &["--required", REQUIRED, "--answered", ANSWERED]);
    assert_eq!(code, 3, "not landable, and not worth another look");
    // THE VERDICT WORD, NOT THE SUBSTRING. `contains("red")` matches inside
    // "requi**red** check" and passes over any output at all — the anchored
    // spelling is the one that discriminates.
    assert!(
        !stdout.contains("checks green: red"),
        "no failure is promoted: {stdout}"
    );
    assert!(stdout.contains("checks green: dead-end"), "{stdout}");
}

/// CLOUD-497 at the boundary: a closed masked set exits `3`, an open one does not.
///
/// The unit tier decides the predicate; this asserts the thing only a process can
/// show — that the distinction survives as an EXIT CODE, which is all `ci-wait`'s
/// adapter and `land`'s lap can read. A split that reached the right verdict and
/// then collapsed both onto `2` at the boundary would fix nothing: the poll would
/// still ask again.
///
/// Measured input, PR #378 head `f5ac94f8`: `ci`'s newest run is a `skipped`
/// minted six minutes after its own success, over siblings that graded.
#[test]
fn a_closed_masked_set_exits_three_and_an_open_one_does_not() {
    let closed = "completed\tskipped\tci\t2026-08-12T21:58:23Z\t94276140437\n\
                  completed\tsuccess\tperf\t2026-08-12T21:52:23Z\t94274706740\n\
                  completed\tsuccess\tfinal\t2026-08-12T21:59:13Z\t94276319070";
    let (code, stdout, stderr) = green(closed, &roster());
    assert_eq!(code, 3, "a closed masked set is not worth another look");
    assert!(stdout.contains("checks green: dead-end"), "{stdout}");
    assert!(stdout.contains("ci skipped"), "{stdout}");
    // The remedy is on stderr and names what buys a fresh run, because a reader
    // who stops here has to do something and the code alone cannot say what.
    assert!(stderr.contains("re-ready"), "{stderr}");

    // MIRROR: the same mask with one sibling still running is `2` and "pending",
    // so the poller keeps waiting — unbounded, exactly as before this row.
    let open = "completed\tskipped\tci\t2026-08-12T21:58:23Z\t94276140437\n\
                in_progress\t-\tperf\t2026-08-12T21:52:23Z\t94274706740\n\
                completed\tsuccess\tfinal\t2026-08-12T21:59:13Z\t94276319070";
    let (code, stdout, _) = green(open, &roster());
    assert_eq!(code, 2, "an answer may still arrive: {stdout}");
    assert!(stdout.contains("checks green: pending"), "{stdout}");

    // MIRROR: a terminal set with nothing masked is still green, so the new arm
    // costs the ordinary landing path nothing.
    let (code, _, _) = green(&all_green(), &roster());
    assert_eq!(code, 0);
}

#[test]
fn an_unrelated_check_gets_neither_a_vote_nor_a_veto() {
    // The scoping that stops a third party vetoing a landing — the same reason
    // the roster exists rather than "any graded run".
    let reading = format!("{}\ncompleted\tfailure\tSomeAnalyzer\t\t0", all_green());
    let (code, _, _) = green(&reading, &roster());
    assert_eq!(code, 0);
}

#[test]
fn the_output_is_a_pointer_and_never_a_log() {
    // Rule 4. The type carrying a finding has room for a name and a conclusion
    // and nothing else, so this asserts the boundary honours that rather than
    // re-deriving it: a run's detail must not appear even when the caller asked
    // about a failure.
    let (_, stdout, stderr) = green("completed\tfailure\tci\t\t0", &roster());
    assert!(stdout.contains("ci failure"), "{stdout}");
    for surface in [&stdout, &stderr] {
        assert!(
            !surface.contains("http"),
            "no url reaches the output: {surface}"
        );
    }
}

// ---------------------------------------------------------------------------
// `--sha`: the reading taken in process (CLOUD-843), against the fixture forge.
//
// The `checks-green` task's acquisition was `gh api .../check-runs --jq` with
// every failure mapped to could-not-look. These pin that the verb reads the
// commit it was NAMED, and that a declined read stays could-not-look rather than
// collapsing into an empty reading — which would decide as "not yet" and be
// polled on forever.
// ---------------------------------------------------------------------------

/// The repository the fixture forge answers for.
const FETCH_REPO: &str = "acme/widgets";

/// The commit the fetch cases name.
const FETCH_SHA: &str = "0123456789abcdef0123456789abcdef01234567";

/// A fixture forge whose first answer is `status` over `body`.
fn forge(name: &str, status: u16, body: &str) -> std::path::PathBuf {
    let dir = common::scratch(&format!("checks-green-fetch-{name}"));
    std::fs::write(
        dir.join("resp.1"),
        format!("HTTP/2 {status}\ncontent-type: application/json\n\n{body}\n"),
    )
    .expect("write the canned answer");
    dir
}

/// `batten checks green --sha FETCH_SHA --repo FETCH_REPO` against `forge`.
fn fetched(forge: &std::path::Path) -> std::process::Output {
    common::batten()
        .args(["checks", "green", "--sha", FETCH_SHA, "--repo", FETCH_REPO])
        .args(roster())
        .env("BATTEN_REST_FIXTURE", forge)
        .output()
        .expect("the compiled binary runs")
}

#[test]
fn the_fetched_reading_is_the_named_commits() {
    let runs = ["ci", "perf", "final"]
        .iter()
        .enumerate()
        .map(|(i, name)| {
            format!(
                r#"{{"name": "{name}", "status": "completed", "conclusion": "success", "started_at": "2026-08-12T00:00:00Z", "completed_at": "2026-08-12T00:01:00Z", "id": {}}}"#,
                i + 1
            )
        })
        .collect::<Vec<_>>();
    let dir = forge(
        "green",
        200,
        &format!(
            r#"{{"total_count": {}, "check_runs": [{}]}}"#,
            runs.len(),
            runs.join(", ")
        ),
    );
    let out = fetched(&dir);
    let stdout = common::stdout(&out);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{stdout}{}",
        common::stderr(&out)
    );
    assert!(stdout.contains("checks green: green"), "{stdout}");
    // THE REQUEST, NOT ONLY THE ANSWER: the fixture serves any path, so a verb
    // that read some other commit would still print green over this body.
    let asked = std::fs::read_to_string(dir.join("args")).expect("the forge was asked");
    assert!(
        asked.contains(&format!(
            "repos/{FETCH_REPO}/commits/{FETCH_SHA}/check-runs"
        )),
        "{asked}"
    );
}

#[test]
fn a_declined_forge_read_is_could_not_look_never_not_yet() {
    // An unpushed sha answers 404, and the retired task's `gh api` failure arm
    // made that could-not-look. Read as an empty reading instead, every required
    // name would be unregistered: `pending`, exit 2, and a poll with no end.
    let dir = forge("declined", 404, r#"{"message": "No commit found for SHA"}"#);
    let out = fetched(&dir);
    let stdout = common::stdout(&out);
    let stderr = common::stderr(&out);
    assert_eq!(out.status.code(), Some(3), "{stdout}{stderr}");
    assert!(stderr.contains("could not look"), "{stderr}");
    assert!(!stdout.contains("checks green: pending"), "{stdout}");
}

#[test]
fn a_repo_without_a_sha_is_a_usage_error() {
    // `--repo` names what `--sha` reads. Beside a piped reading it scopes
    // nothing, and accepting it would let a caller believe it had.
    let (code, _, stderr) = green(&all_green(), &{
        let mut args = roster();
        args.extend(["--repo", FETCH_REPO]);
        args
    });
    assert_eq!(code, 1, "{stderr}");
}

// ---------------------------------------------------------------------------
// `[tasks."checks-green"]`: the committed task, run through mise (CLOUD-843).
//
// The task's bash body retired onto one argv over this verb. Every case below
// runs the COMMITTED task with `mise run`, the engine this suite built first on
// `PATH` and the fixture forge answering — so mise's own templating binds `$SHA`,
// `$REPO` and the `[env]` roster exactly as a workflow's call does, and a case
// asserts the declared task rather than a copy of it.
//
// RETIREMENT LEDGER for the body, per behaviour — what `shell retire partial`
// reads:
//
// carried: "[tasks.checks-green] body" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/checks_green.rs
// carried: "checks-green: $SHA names the commit, else the checkout's HEAD" crates/batten/src/lib.rs kind:mechanism crates/batten/tests/it/checks_green.rs
// carried: "checks-green: $REPO names the repository, else the checkout's forge remote" mise.toml kind:mechanism crates/batten/tests/it/checks_green.rs
// carried: "checks-green: the roster is the four CI_* values in [env]" mise.toml kind:mechanism crates/batten/tests/it/checks_green.rs
// carried: "checks-green: a green head is 0" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/checks_green.rs
// carried: "checks-green: a closed set with a masked name is 3 and says dead-end (CLOUD-497)" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/checks_green.rs
// carried: "checks-green: the engine's answer is printed" crates/batten/src/lib.rs kind:verb crates/batten/tests/it/checks_green.rs
// changed: "checks-green: a red head is 1" crates/batten/src/lib.rs kind:verb exit 2 on the engine's table where the body said 1; the word `red` still travels on stdout and as `verdict` in the `--json` document, which is what `auto-bot-land.yml` reads to freeze a red head. One exit table, no per-verb exception (house-style §7)
// changed: "checks-green: a head with no answer yet is 3" crates/batten/src/lib.rs kind:verb exit 2 where the body said 3, sharing it with red because both mean "may not land"; the word is `pending`
// changed: "checks-green: a reading that could not be taken is 2" crates/batten/src/lib.rs kind:verb exit 3 where the body said 2, sharing it with a dead end (CLOUD-497); a could-not-look prints no verdict word at all, so a `--json` caller tells the two apart by the word's absence, as `auto-release-land.yml` and `auto-bot-land.yml` do
// changed: "checks-green: no $SHA and no git HEAD is could-not-look" crates/batten/src/lib.rs kind:verb the literal `HEAD` a checkout cannot resolve reaches the forge as written and is refused there — could-not-look still, at exit 3 where the body said 2, and never a pass
// changed: "checks-green: an unusable roster is 2" crates/batten/src/lib.rs kind:verb the engine's usage error, exit 1, which `an_unusable_roster_is_a_usage_error_and_not_the_policy_verdict` pins over the verb the task runs; mise's `[env]` outranks a caller's environment, so the task tier cannot empty the committed roster to re-assert it
// changed: "checks-green: CHECKS_GREEN_RUNS injects a reading, and an explicitly empty one is no answer yet without the network" crates/batten/src/lib.rs kind:verb the injection seam went with the pipe it fed: a reading in hand is `batten checks green` without `--sha`, deciding over stdin, and an empty one is still `pending` with no network — `every_non_green_state_exits_non_zero`'s "nothing registered yet" row

/// The committed `[env]` value `key`, split into names the way the verb splits it.
fn committed_env(key: &str) -> Vec<String> {
    let manifest: toml::Value = toml::from_str(
        &std::fs::read_to_string(common::at_root("mise.toml")).expect("the manifest"),
    )
    .expect("mise.toml parses");
    manifest["env"][key]
        .as_str()
        .unwrap_or_else(|| panic!("[env] {key} is a plain string"))
        .split(',')
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// The required names that must REGISTER for a head to be green: the roster
/// less the names whose absence it tolerates.
fn must_register() -> Vec<String> {
    let absent_ok = committed_env("CI_ABSENT_OK_CHECKS");
    committed_env("CI_REQUIRED_CHECKS")
        .into_iter()
        .filter(|name| !absent_ok.contains(name))
        .collect()
}

/// One check-run as the endpoint returns it.
fn check_run(name: &str, status: &str, conclusion: Option<&str>, id: usize) -> serde_json::Value {
    let completed = (status == "completed").then_some("2026-08-12T00:01:00Z");
    serde_json::json!({
        "name": name,
        "status": status,
        "conclusion": conclusion,
        "started_at": "2026-08-12T00:00:00Z",
        "completed_at": completed,
        "id": id,
    })
}

/// A page in which every registering name concluded `siblings` (success when
/// `None`), except `name`, whose run is `status`/`conclusion`.
fn reading(name: &str, status: &str, conclusion: Option<&str>, siblings: Option<&str>) -> String {
    let runs: Vec<serde_json::Value> = must_register()
        .iter()
        .enumerate()
        .map(|(i, each)| {
            if each == name {
                check_run(each, status, conclusion, i + 1)
            } else {
                check_run(
                    each,
                    "completed",
                    Some(siblings.unwrap_or("success")),
                    i + 1,
                )
            }
        })
        .collect();
    serde_json::json!({"total_count": runs.len(), "check_runs": runs}).to_string()
}

/// A checkout with one commit and a forge remote, and the commit's sha.
fn checkout(name: &str) -> (std::path::PathBuf, String) {
    let dir = common::scratch(&format!("checks-green-task-{name}"));
    common::init_repo(&dir);
    common::git_in(
        &dir,
        &[
            "remote",
            "add",
            "origin",
            "https://github.com/example/example.git",
        ],
    );
    common::git_in(&dir, &["commit", "--quiet", "--allow-empty", "-m", "base"]);
    let head = common::git_in(&dir, &["rev-parse", "HEAD"])
        .trim()
        .to_owned();
    (dir, head)
}

/// `mise run checks-green <args>` in `dir`, against `forge`, with `env` set.
fn task(
    dir: &std::path::Path,
    forge: &std::path::Path,
    args: &str,
    env: &[(&str, &str)],
) -> std::process::Output {
    let forge = forge.to_str().expect("a utf-8 scratch path").to_owned();
    let mut all: Vec<(&str, &str)> = vec![("BATTEN_REST_FIXTURE", forge.as_str())];
    all.extend_from_slice(env);
    common::mise_task(dir, &format!("checks-green {args}"), &all, "")
}

/// The `verdict` word of the task's `--json` document, if it printed one.
fn verdict_word(output: &std::process::Output) -> Option<String> {
    common::stdout(output)
        .lines()
        .filter(|line| line.starts_with('{'))
        .find_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .and_then(|document| document["verdict"].as_str().map(ToOwned::to_owned))
}

/// The committed task is one argv over the verb: no shell key and no character
/// a shell would interpret, so what runs is exactly what is written.
#[test]
fn the_task_is_one_argv_over_the_verb() {
    let block = common::task_block("checks-green").expect("[tasks.\"checks-green\"] is declared");
    assert_eq!(common::task_value(&block, "shell"), "", "no shell is named");
    let run = common::task_value(&block, "run");
    assert!(run.starts_with("batten checks green --sha "), "{run}");
    assert!(
        !batten::census::shell_syntax(&run),
        "an argv, not a shell body: {run}"
    );
    for key in [
        "CI_REQUIRED_CHECKS",
        "CI_ABSENT_OK_CHECKS",
        "CI_ANSWERED_CONCLUSIONS",
        "CI_FANIN_CHECK",
    ] {
        assert!(
            run.contains(&format!("'{{{{env.{key}}}}}'")),
            "{key} reaches a flag, quoted: {run}"
        );
    }
}

/// `--sha HEAD` is the checkout's commit by the time the forge is asked: the
/// request carries the resolved sha, never the ref (`ref-unresolved`).
#[test]
fn the_task_names_the_checkouts_head_by_its_commit() {
    let (dir, head) = checkout("head");
    let names = must_register();
    let forge = forge(
        "task-head",
        200,
        &reading(&names[0], "completed", Some("success"), None),
    );
    let output = task(&dir, &forge, "", &[("SHA", ""), ("REPO", "")]);
    let asked = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
    assert!(
        asked.contains(&format!("repos/example/example/commits/{head}/check-runs")),
        "the request names the resolved commit on the checkout's remote: {asked}\n{}",
        common::stderr(&output)
    );
    assert!(
        !asked.contains("commits/HEAD/"),
        "and never the ref itself: {asked}"
    );
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
}

/// `$SHA` and `$REPO` still name the commit and the repository, as the body's
/// `${SHA:-…}` and `${REPO:-…}` did (`sha-override-ignored`,
/// `repo-override-ignored`).
#[test]
fn the_task_reads_the_named_sha_from_the_named_repo() {
    let (dir, head) = checkout("named");
    let names = must_register();
    let forge = forge(
        "task-named",
        200,
        &reading(&names[0], "completed", Some("success"), None),
    );
    let output = task(
        &dir,
        &forge,
        "",
        &[("SHA", FETCH_SHA), ("REPO", FETCH_REPO)],
    );
    let asked = std::fs::read_to_string(forge.join("args")).unwrap_or_default();
    assert!(
        asked.contains(&format!(
            "repos/{FETCH_REPO}/commits/{FETCH_SHA}/check-runs"
        )),
        "{asked}\n{}",
        common::stderr(&output)
    );
    assert!(
        !asked.contains(&head),
        "the checkout's own head is not asked about: {asked}"
    );
    assert_eq!(output.status.code(), Some(0), "{}", common::stderr(&output));
}

/// THE TABLE, over the committed roster: every state's code AND its word, the
/// word being what a workflow reads where two states share a code
/// (`fanin-dropped`, `absent-ok-dropped`).
#[test]
fn the_task_answers_the_engines_table_with_the_word_on_stdout() {
    let names = must_register();
    let fanin = committed_env("CI_FANIN_CHECK");
    let first = names
        .iter()
        .find(|name| !fanin.contains(name))
        .expect("a required name that is not the fan-in")
        .clone();
    let cases: [(&str, String, i32, &str); 4] = [
        // Every registering name green, and every absent-ok name absent — which
        // only the `--absent-ok` flag reaching the verb makes green.
        (
            "green",
            reading(&first, "completed", Some("success"), None),
            0,
            "green",
        ),
        // CLOUD-900: a non-fan-in failure over cancelled siblings is the verdict.
        // Without `--fanin` it is a dead end, so the fan-in reaching the verb is
        // what this row sees.
        (
            "red",
            reading(&first, "completed", Some("failure"), Some("cancelled")),
            2,
            "red",
        ),
        (
            "pending",
            reading(&first, "in_progress", None, None),
            2,
            "pending",
        ),
        // CLOUD-497: a closed set whose latest run of one name is a skip.
        (
            "dead-end",
            reading(&first, "completed", Some("skipped"), None),
            3,
            "dead-end",
        ),
    ];
    let env = [("SHA", FETCH_SHA), ("REPO", FETCH_REPO)];
    for (what, body, code, word) in cases {
        let (dir, _) = checkout(&format!("table-{what}"));
        let json_forge = forge(&format!("task-table-{what}"), 200, &body);
        let json = task(&dir, &json_forge, "--json", &env);
        assert_eq!(
            json.status.code(),
            Some(code),
            "{what}: {}{}",
            common::stdout(&json),
            common::stderr(&json)
        );
        assert_eq!(
            verdict_word(&json).as_deref(),
            Some(word),
            "{what}: {}",
            common::stdout(&json)
        );
        // And the plain task prints the engine's line with the same word.
        let plain_forge = forge(&format!("task-table-{what}-plain"), 200, &body);
        let plain = task(&dir, &plain_forge, "", &env);
        assert_eq!(plain.status.code(), Some(code), "{what}");
        assert!(
            common::stdout(&plain).contains(&format!("checks green: {word} ")),
            "{what}: {}",
            common::stdout(&plain)
        );
    }
}

/// A reading the forge declines is could-not-look: exit 3, and NO verdict word,
/// which is how a `--json` caller tells it from a dead end at the same code.
#[test]
fn a_declined_read_through_the_task_is_could_not_look_with_no_word() {
    let (dir, _) = checkout("declined");
    let forge = forge(
        "task-declined",
        404,
        r#"{"message": "No commit found for SHA"}"#,
    );
    let output = task(
        &dir,
        &forge,
        "--json",
        &[("SHA", FETCH_SHA), ("REPO", FETCH_REPO)],
    );
    assert_eq!(output.status.code(), Some(3), "{}", common::stderr(&output));
    assert_eq!(verdict_word(&output), None, "{}", common::stdout(&output));
    assert!(
        common::stderr(&output).contains("could not look"),
        "{}",
        common::stderr(&output)
    );
}
