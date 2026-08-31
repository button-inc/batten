//! `batten pr watch` polls over the compiled binary (CLOUD-1143).
//!
//! # Why this tier
//!
//! `pr_watch.rs`'s own unit cases pin the PARSE and the fold — a `304` keeping
//! the reading, a floor raising the interval, a body projecting to rows. None of
//! them can pin the two things a caller actually depends on, because neither
//! exists until there is a process: that the loop **turns**, re-reading until
//! the answer changes, and the **exit code** each terminal verdict maps to.
//!
//! A `with input as`-shaped test cannot reach either. This one drives the real
//! binary against a stubbed client on `PATH`, which is the same instrument the
//! retired bats suite used and the reason its cases port at all: the responses
//! are canned, so an all-skipped set, a cancelled set and a conditional `304`
//! are reproducible without waiting on real CI.
//!
//! # The one thing this tier must never do
//!
//! Hang. The poll is deliberately unbounded, so every case's LAST response has
//! to be one the roster reads as terminal — otherwise a wrong answer arrives as
//! a suite that never finishes rather than as a failure. The retired suite hit
//! exactly that twice, for the better part of an hour each time, when the real
//! roster grew a name its hand-written fixture did not know. The roster here is
//! passed as flags and is the fixture's own, so it cannot drift out from under
//! the responses.

// THE FILE-GRANULARITY RETIREMENT ARMS. Two paths die, so two arms: a program
// and its suite are separate subjects, and one arm covering both would claim a
// conservation nobody checked.
//
// carried: mise-tasks/ci-wait.sh crates/batten/src/pr_watch.rs kind:verb crates/batten/tests/pr_watch.rs
// carried: tests/ci-wait.bats crates/batten/src/pr_watch.rs kind:verb crates/batten/tests/pr_watch.rs
//
// CLOUD-908's case arms: every `@test` the retired suite declared. Nine carried
// and four changed, and each change is a SEAM the port moved rather than a
// predicate it dropped.
//
// carried: "green set exits 0 and prints each conclusion" crates/batten/src/pr_watch.rs kind:verb
// carried: "the check-runs request asks for a full page, not the default 30 (CLOUD-337)" crates/batten/src/pr_watch.rs kind:verb
// carried: "an all-skipped set is not green, and the poll continues" crates/batten/src/pr_watch.rs kind:verb
// carried: "a draft-era skip set with third-party successes is not green" crates/batten/src/pr_watch.rs kind:verb
// carried: "a cancelled set holds the poll open instead of reporting red" crates/batten/src/pr_watch.rs kind:verb
// carried: "a third-party check gets no veto over landing" crates/batten/src/pr_watch.rs kind:verb
// carried: "a required check still pending holds the poll open" crates/batten/src/pr_watch.rs kind:verb
// carried: "a 304 keeps the previous reading instead of clearing it" crates/batten/src/pr_watch.rs kind:verb
// carried: "a server-requested poll floor is honoured over a shorter interval" crates/batten/src/pr_watch.rs kind:verb
//
// changed: "a failing check exits 1" crates/batten/src/pr_watch.rs kind:verb the predicate is conserved exactly — a required failure TERMINATES the poll with a refusal — but the number is the engine's now. `exit.rs` is total with no per-verb exception, so a policy verdict is `Violation` (2) wherever it is raised, and `1` means a usage error. It survives as `a_red_head_terminates_the_poll_with_the_policy_verdict`
// changed: "ci-wait.bats::a required check that failed is red, and named" crates/batten/src/pr_watch.rs kind:verb the same renumbering, and the naming half is unchanged: the failing check still reaches the caller as a pointer. It survives as `a_red_head_names_the_check_that_failed`
// changed: "ci-wait.bats::an unset required set is fatal rather than an empty one" crates/batten/src/pr_watch.rs kind:verb the suite asserted an UNSET ENVIRONMENT VARIABLE was fatal, and the verb has no such variable to leave unset — the roster arrives as a flag, so the caller keeps its own authority for where it is written down and the core holds no consumer's name (rule 1, CLOUD-772). The property that mattered survives as `an_empty_roster_is_refused_before_a_single_request`, which adds the half the shell could not have: the refusal happens BEFORE the unbounded loop, so a typo is a message rather than a hang
// changed: "every poll pushes a tick, so a blocked loop is distinguishable from a waiting one" crates/batten/src/pr_watch.rs kind:verb both signals are conserved and so is the counting property — one tick per poll, exactly, plus a signature — but WHICH program records them is the caller's now rather than a sibling resolved by path, because a recorder's path under `crates/batten` is non-negotiable rule 1's violation. It survives as `every_poll_pushes_a_tick_and_a_signature`, over a stub recorder the case supplies

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::{Path, PathBuf};

/// The roster these cases decide against.
///
/// Passed as flags and small on purpose. The retired suite derived its green set
/// from the repository's live roster, which is what let a newly required check
/// turn a wrong answer into an hour-long hang; here the roster and the responses
/// are one fixture and cannot disagree.
const REQUIRED: &str = "ci,cross,final";
const ANSWERED: &str = "success,neutral,failure,timed_out,action_required";

/// A response whose header block carries `etag`, followed by `body`.
fn response(etag: &str, body: &str) -> String {
    format!("HTTP/2.0 200 OK\r\nETag: {etag}\r\n\r\n{body}\n")
}

/// A reading in which every required name is terminal and green, plus whatever
/// extra rows a case appends.
fn all_green(extra: &str) -> String {
    let rows = ["ci", "cross", "final"]
        .iter()
        .map(|name| format!(r#"{{"status":"completed","conclusion":"success","name":"{name}"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    format!("{{\"check_runs\":[{rows}{extra}]}}")
}

/// A fixture: a scratch directory holding a stubbed client, the responses it
/// replays in order, and the argv it was called with.
struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    /// Materialize a fixture whose client replays `responses` in order and then
    /// repeats the last one forever.
    ///
    /// Repeating the last is what bounds the loop: the poll is unbounded by
    /// design, so the final response must be one the roster reads as terminal.
    fn new(name: &str, responses: &[String]) -> Self {
        let dir = common::scratch(name);
        let bin = dir.join("bin");
        std::fs::create_dir_all(&bin).expect("create the stub directory");
        for (index, body) in responses.iter().enumerate() {
            std::fs::write(dir.join(format!("resp.{}", index + 1)), body).expect("write response");
        }
        std::fs::write(
            dir.join("resp.last"),
            responses.last().expect("at least one response"),
        )
        .expect("write the terminal response");

        let root = dir.display().to_string();
        write_program(
            &bin.join("gh"),
            &format!(
                "#!/usr/bin/env bash\n\
                 n=$(cat '{root}/calls' 2>/dev/null || echo 0)\n\
                 echo $((n + 1)) >'{root}/calls'\n\
                 printf '%s\\n' \"$*\" >>'{root}/args'\n\
                 cat '{root}/resp.'$((n + 1)) 2>/dev/null || cat '{root}/resp.last'\n"
            ),
        );
        // The recorder is a program the CALLER names, so the fixture supplies
        // one: it appends its argv, which is what makes "one push per poll"
        // countable rather than sampled.
        write_program(
            &bin.join("recorder"),
            &format!("#!/usr/bin/env bash\nprintf '%s\\n' \"$*\" >>'{root}/signals'\n"),
        );
        Self { dir }
    }

    /// Run `batten pr watch` against this fixture with the ordinary flags, plus
    /// whatever `extra` a case adds.
    ///
    /// `--interval 0`, because the interval is a rate-limit economy and this
    /// fixture has no rate limit. The FLOOR case is the one place the number
    /// itself is the subject.
    fn watch(&self, extra: &[&str]) -> (i32, String, String) {
        let mut args = vec![
            "--sha",
            "deadbeef",
            "--interval",
            "0",
            "--required",
            REQUIRED,
            "--answered",
            ANSWERED,
            "--fanin",
            "final",
        ];
        args.extend_from_slice(extra);
        self.watch_with(&args)
    }

    /// Run `batten pr watch` with EXACTLY these flags.
    ///
    /// The invocation-error cases need this rather than `wait`: clap refuses a
    /// repeated `--required` before the verb runs, so a case that overrode a
    /// flag by appending would assert the parser's refusal instead of the
    /// verb's — a green that proves nothing about the property it names.
    fn watch_with(&self, args: &[&str]) -> (i32, String, String) {
        // `join_paths`, never an interpolated separator: it is `;` on Windows,
        // where a path begins `D:\` — so a `format!` there yields a PATH whose
        // first entry is a drive letter and whose second swallows the rest
        // (CLOUD-617). `primitives.rs` is the gate on that.
        let mut entries = vec![self.dir.join("bin")];
        entries.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        let path = std::env::join_paths(entries).expect("the stub directory joins into a PATH");
        let output = common::batten()
            .arg("pr")
            .arg("watch")
            .args(args)
            .env("PATH", path)
            .current_dir(&self.dir)
            .output()
            .expect("the compiled binary runs");
        (
            output.status.code().expect("the child exited normally"),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn calls(&self) -> u32 {
        std::fs::read_to_string(self.dir.join("calls"))
            .map_or(0, |raw| raw.trim().parse().unwrap_or(0))
    }

    fn args(&self) -> String {
        std::fs::read_to_string(self.dir.join("args")).unwrap_or_default()
    }

    fn signals(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("signals"))
            .unwrap_or_default()
            .lines()
            .map(ToOwned::to_owned)
            .collect()
    }
}

fn write_program(path: &Path, body: &str) {
    std::fs::write(path, body).expect("write the stub program");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
            .expect("make the stub executable");
    }
}

// ---------------------------------------------------------------------------
// The terminal verdicts, which are what a caller branches on.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_green_head_exits_zero_and_prints_each_conclusion() {
    let fixture = Fixture::new("ci-wait-green", &[response("W/\"a\"", &all_green(""))]);
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "a green head is the only zero: {stdout}");
    // One pointer per judged name, which is the view the predecessor emitted
    // from inside the same pass the verdict was taken in.
    assert!(stdout.contains("ci success"), "{stdout}");
    assert!(stdout.contains("cross success"), "{stdout}");
    assert!(stdout.contains("terminal and green"), "{stdout}");
}

// THE REQUEST IS PART OF THE PREDICATE (CLOUD-337). This endpoint returns a run
// per EVENT per name, so a head that has been readied, re-drafted and re-readied
// clears the default page without anything unusual happening — and nothing here
// fetches page 2. Under CLOUD-337 a truncated name reads as ABSENT, so the
// failure mode is a stall; before it, it was a false green.
#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn the_request_asks_for_a_full_page_rather_than_the_default() {
    let fixture = Fixture::new("ci-wait-page", &[response("W/\"a\"", &all_green(""))]);
    let (code, _, _) = fixture.watch(&[]);
    assert_eq!(code, 0);
    assert!(
        fixture.args().contains("check-runs?per_page=100"),
        "{}",
        fixture.args()
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_red_head_terminates_the_poll_with_the_policy_verdict() {
    // The reading is deliberately a bare `ci failure` with the other required
    // names ABSENT, which makes this the poll-level statement of CLOUD-337's
    // ordering: a real failure outranks a name that has not registered, so the
    // poll stops here rather than holding open for stragglers on a tree already
    // known to be red. Do not "fix" it by adding the green rows; that is the one
    // edit that would silently retire the assertion.
    let fixture = Fixture::new(
        "ci-wait-red",
        &[response(
            "W/\"a\"",
            r#"{"check_runs":[{"status":"completed","conclusion":"failure","name":"ci"}]}"#,
        )],
    );
    let (code, _, stderr) = fixture.watch(&[]);
    assert_eq!(code, 2, "a red head is the policy verdict: {stderr}");
    assert!(stderr.contains("not green"), "{stderr}");
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_red_head_names_the_check_that_failed() {
    let fixture = Fixture::new(
        "ci-wait-red-named",
        &[response(
            "W/\"a\"",
            r#"{"check_runs":[
                {"status":"completed","conclusion":"success","name":"ci"},
                {"status":"completed","conclusion":"failure","name":"cross"}]}"#,
        )],
    );
    let (code, stdout, stderr) = fixture.watch(&[]);
    assert_eq!(code, 2, "{stderr}");
    assert!(stderr.contains("cross failure"), "{stderr}");
    // ...and the judged view still reaches stdout, so the summary and the
    // verdict cannot contradict each other.
    assert!(stdout.contains("ci success"), "{stdout}");
}

// ---------------------------------------------------------------------------
// The states that must NOT terminate the poll. Each fixture's last response is
// green, so a case that wrongly stops early fails on the code and a case that
// wrongly holds open would hang — which is why the last response exists.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn an_all_skipped_set_is_not_an_answer_and_the_poll_continues() {
    // The draft-era runs look terminal and unfailed. Treating them as an answer
    // would clear a head whose CI never ran.
    let fixture = Fixture::new(
        "ci-wait-skipped",
        &[
            response(
                "W/\"a\"",
                r#"{"check_runs":[{"status":"completed","conclusion":"skipped","name":"ci"}]}"#,
            ),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(fixture.calls() >= 2, "the poll must have turned again");
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_draft_era_skip_set_with_third_party_successes_is_not_green() {
    // The set that landed #261 (CLOUD-327), in shape: every check that judges
    // this repository is a draft-era `skipped`, and the workflows that are not
    // draft-gated graded on their own. The old predicate counted those two and
    // reported "all checks terminal and green".
    let fixture = Fixture::new(
        "ci-wait-draft-skips",
        &[
            response(
                "W/\"a\"",
                r#"{"check_runs":[
                    {"status":"completed","conclusion":"success","name":"an external analyzer"},
                    {"status":"completed","conclusion":"skipped","name":"ci"},
                    {"status":"completed","conclusion":"skipped","name":"cross"},
                    {"status":"completed","conclusion":"skipped","name":"final"}]}"#,
            ),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(fixture.calls() >= 2);
    // And it says what it is waiting on, as a pointer rather than a log.
    assert!(stdout.contains("no verdict"), "{stdout}");
    assert!(stdout.contains("ci skipped"), "{stdout}");
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_cancelled_set_holds_the_poll_open_instead_of_reporting_red() {
    // CLOUD-363, through the poll rather than the predicate: the supersession
    // that cancelled #293's landing run made the poll report red, the landing
    // re-draft, and the branch wedge. The poll must outlive the cancellation,
    // because the next lap re-fires the ready and the fresh run supersedes these
    // check runs by name. `final` is the fan-in, so its failure here is
    // MANUFACTURED by the cancellations rather than a verdict (CLOUD-900).
    let fixture = Fixture::new(
        "ci-wait-cancelled",
        &[
            response(
                "W/\"a\"",
                r#"{"check_runs":[
                    {"status":"completed","conclusion":"failure","name":"final"},
                    {"status":"completed","conclusion":"cancelled","name":"ci"},
                    {"status":"completed","conclusion":"cancelled","name":"cross"}]}"#,
            ),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(fixture.calls() >= 2);
    assert!(stdout.contains("ci cancelled"), "{stdout}");
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_third_party_check_gets_no_veto_over_landing() {
    // Branch protection enforces the required set, so a failure outside it must
    // not hold the trunk. The mirror of the case above: same scoping, other sign.
    let fixture = Fixture::new(
        "ci-wait-third-party",
        &[response(
            "W/\"a\"",
            &all_green(
                r#",{"status":"completed","conclusion":"failure","name":"an external analyzer"}"#,
            ),
        )],
    );
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_required_check_still_running_holds_the_poll_open() {
    // A third-party check that has already graded must not make the set look
    // terminal while one of ours is still running.
    let fixture = Fixture::new(
        "ci-wait-pending",
        &[
            response(
                "W/\"a\"",
                r#"{"check_runs":[
                    {"status":"completed","conclusion":"success","name":"an external analyzer"},
                    {"status":"in_progress","conclusion":null,"name":"ci"}]}"#,
            ),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(fixture.calls() >= 2);
}

// A CONDITIONAL REQUEST THAT FINDS NO CHANGE HAS NO BODY. Re-parsing that as an
// empty check set would restart the wait on every unchanged poll — and the
// unit case pins the fold, while this pins that the loop actually survives one.
#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_304_keeps_the_previous_reading_instead_of_clearing_it() {
    let fixture = Fixture::new(
        "ci-wait-304",
        &[
            response(
                "W/\"a\"",
                r#"{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}"#,
            ),
            String::from("HTTP/2.0 304 Not Modified\r\nETag: W/\"a\"\r\n\r\n"),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(fixture.calls() >= 3, "the 304 must not have ended the poll");
    // The second request carried the validator the first response issued, which
    // is the whole economy: a 304 costs no rate limit and that is what pays for
    // a short interval.
    assert!(
        fixture.args().contains("If-None-Match: W/\"a\""),
        "{}",
        fixture.args()
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_server_requested_poll_floor_is_honoured_over_a_shorter_interval() {
    // The floor is the endpoint asking to be polled less often, so it wins over
    // the configured interval. Asserted end to end rather than only in the fold,
    // because a floor the loop parses and then ignores looks identical here.
    let fixture = Fixture::new(
        "ci-wait-floor",
        &[
            format!(
                "HTTP/2.0 200 OK\r\nETag: W/\"a\"\r\nX-Poll-Interval: 1\r\n\r\n{}\n",
                r#"{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}"#
            ),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let started = std::time::Instant::now();
    let (code, stdout, _) = fixture.watch(&[]);
    assert_eq!(code, 0, "{stdout}");
    assert!(
        started.elapsed() >= std::time::Duration::from_secs(1),
        "a `--interval 0` run that honoured a 1s floor cannot finish sooner than the floor"
    );
}

// ---------------------------------------------------------------------------
// The two progress signals (CLOUD-499).
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn every_poll_pushes_a_tick_and_a_signature() {
    // This loop is the only thing in a landing that iterates faster than a lease
    // heartbeat, and it used to push nothing at all — a heartbeat reading only a
    // phase could not tell a healthy wait from a wedged client. One tick per
    // poll, COUNTED rather than sampled: the tick is the poll counter, so the
    // two must agree exactly or a poll went unrecorded.
    let fixture = Fixture::new(
        "ci-wait-progress",
        &[
            response(
                "W/\"a\"",
                r#"{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}"#,
            ),
            response("W/\"b\"", &all_green("")),
        ],
    );
    let (code, stdout, _) = fixture.watch(&["--progress", "recorder", "--progress-id", "4242"]);
    assert_eq!(code, 0, "{stdout}");

    let signals = fixture.signals();
    let ticks: Vec<&String> = signals
        .iter()
        .filter(|line| line.starts_with("tick "))
        .collect();
    let sigs: Vec<&String> = signals
        .iter()
        .filter(|line| line.starts_with("sig "))
        .collect();
    assert_eq!(
        u32::try_from(ticks.len()).unwrap(),
        fixture.calls(),
        "one tick per poll, exactly: {signals:?}"
    );
    // The world-moved signal is the other half: a tick that rose while this
    // stayed put is the livelock a hang detector cannot see. Two readings
    // differ here, so it must have moved at least once.
    assert!(sigs.len() >= 2, "{signals:?}");
    assert_ne!(sigs[0], sigs[sigs.len() - 1], "{signals:?}");
    assert!(ticks[0].contains("4242"), "{signals:?}");
}

// ---------------------------------------------------------------------------
// The invocation errors, which are about the CALL and never about the tree.
// ---------------------------------------------------------------------------

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn an_empty_roster_is_refused_before_a_single_request() {
    // An empty set makes every check unrequired, which is the false green this
    // verb exists to stop. Refused BEFORE the loop rather than inside it, which
    // is the half the predecessor could not have: a roster polled forever would
    // be a hang whose cause is a typo.
    let fixture = Fixture::new("ci-wait-no-roster", &[response("W/\"a\"", &all_green(""))]);
    let (code, stdout, stderr) = fixture.watch_with(&[
        "--sha",
        "deadbeef",
        "--required",
        "",
        "--answered",
        ANSWERED,
    ]);
    assert_eq!(code, 1, "an unusable roster is usage, not the verdict");
    assert!(
        stderr.contains("every check would be unrequired"),
        "{stderr}"
    );
    assert_eq!(fixture.calls(), 0, "nothing may be fetched: {stdout}");
    assert!(
        stdout.is_empty(),
        "a refused roster must not announce a poll it never starts: {stdout}"
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn an_interval_that_is_not_a_number_is_a_usage_error_rather_than_a_default() {
    // Swallowing it would put the poll on a cadence nobody asked for, which is
    // invisible until a rate limit says so.
    let fixture = Fixture::new(
        "ci-wait-bad-interval",
        &[response("W/\"a\"", &all_green(""))],
    );
    let (code, _, stderr) = fixture.watch_with(&[
        "--sha",
        "deadbeef",
        "--interval",
        "soon",
        "--required",
        REQUIRED,
        "--answered",
        ANSWERED,
    ]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("whole number of seconds"), "{stderr}");
}

#[test]
#[cfg_attr(not(unix), ignore = "the stubbed client is a shebang script")]
fn a_recorder_without_an_identity_is_refused_rather_than_filed_under_nothing() {
    // Both halves or neither: a recorder with nothing to key on files every
    // landing's signals under one entry, and an identity with no recorder is a
    // caller that believes it is being observed and is not.
    let fixture = Fixture::new(
        "ci-wait-half-progress",
        &[response("W/\"a\"", &all_green(""))],
    );
    let (code, _, stderr) = fixture.watch(&["--progress", "recorder"]);
    assert_eq!(code, 1, "{stderr}");
    assert!(stderr.contains("one setting"), "{stderr}");
}
