//! Block until a head's required checks answer (CLOUD-1143).
//!
//! The poll, ported off `mise-tasks/ci-wait.sh`. It owns the REQUEST — the
//! conditional read, the `ETag`, the interval — and nothing about what green
//! means: that is [`crate::checks_green`]'s, decided over the reading this
//! module already holds. The split is CLOUD-346's and it is why a second,
//! weaker copy of the predicate could not survive in a workflow.
//!
//! # Deliberately unbounded
//!
//! The exit condition is "the required checks reached an answer", which always
//! happens. A wall-clock timeout would only reintroduce the reap gap it was
//! meant to close, so there is none — a caller that wants one supervises the
//! process.
//!
//! # The poll is conditional, and that is what pays for a short interval
//!
//! Each request carries the previous response's `ETag`; when nothing has changed
//! the forge answers `304` with no body, and a `304` does not count against the
//! rate limit (measured: three consecutive conditional requests left the used
//! count unchanged). An unconditional poll had to stay slow to stay affordable,
//! so the news arrived late. A `304` therefore KEEPS the previous reading —
//! re-parsing an absent body as an empty check set would restart the wait on
//! every unchanged poll.
//!
//! # The exit table is the engine's, not the shell's
//!
//! The predecessor used `0` green / `1` red / `2` could-not-look. Under
//! [`crate::exit::ExitCode`], which is total with no per-verb exception, green
//! is `Success`, a red head is `Violation`, an unusable roster is `Usage` and a
//! reading that could not be taken is `Internal`. "Not yet" never reaches the
//! caller at all, because that is the state this loop exists to sit in.
//!
//! # Two progress signals, and neither knows who records them
//!
//! CLOUD-499: this loop is the one thing in a landing that iterates faster than
//! a lease heartbeat, and a heartbeat reading only a phase cannot tell a healthy
//! wait from a wedged one. So it pushes a TICK, which moves every poll and
//! freezes when the loop stops turning, and a SIGNATURE, which moves only when
//! the reading does and freezes when the loop turns forever over something that
//! will never resolve. Both are facts about the poll, so this module names them;
//! WHICH program records them is the caller's, passed in rather than spelled
//! here, because a recorder's path under `crates/batten` is non-negotiable rule
//! 1's violation. Best-effort in every direction: a recorder that fails, or that
//! is not there at all, never changes a verdict.

use std::io::Write;

use anyhow::Result;

use crate::checks_green::{self, Roster, Run, Verdict};
use crate::exit::ExitCode;

/// The forge's own placeholder for "the repository this checkout points at",
/// resolved by the client rather than by us. Named here because it is the
/// TOOL's vocabulary, the same standing `semver.rs` gives its analyser.
pub const REPO_PLACEHOLDER: &str = "{owner}/{repo}";

/// The client this poll reads through.
const CLIENT: &str = "gh";

/// Seconds between requests when the caller names none.
///
/// One second, because the poll is CONDITIONAL: an unchanged reading answers
/// `304` with no body and costs no rate limit, so the interval is not what sets
/// the pace — the round trip is. The predecessor measured ~470ms for the whole
/// conditional call, giving a ~1.5s cycle at this setting.
pub const DEFAULT_INTERVAL: u64 = 1;

/// The page size, and it is part of the predicate rather than a tuning knob.
///
/// This endpoint returns a check-run PER EVENT per name (CLOUD-436), so a
/// nine-name roster over a head that has been readied, re-drafted and re-readied
/// clears the default page without anything unusual happening — and nothing here
/// fetches page 2. Under CLOUD-337 a truncated name reads as ABSENT, so the
/// failure mode is a stall rather than a false green; it was a false green
/// before that landed, which is how it survived unnoticed.
const PER_PAGE: u32 = 100;

/// What the poll needs that is not the roster.
#[derive(Debug, Clone)]
pub struct Config {
    /// The commit whose checks are being read.
    pub sha: String,
    /// The repository, in whatever spelling the client resolves. Defaults to
    /// [`REPO_PLACEHOLDER`].
    pub repo: String,
    /// Seconds between polls, a FLOOR the server may raise and nothing may
    /// lower.
    pub interval: u64,
    /// Where to push the two progress signals, when the caller wants them.
    pub progress: Option<Progress>,
}

/// The caller's progress recorder: a program and the identity it files under.
#[derive(Debug, Clone)]
pub struct Progress {
    /// The program to run. The caller's, never this crate's.
    pub program: String,
    /// The identity the recorder keys on.
    pub id: String,
}

/// One response, split into the three things a conditional poll reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// The status line's code. `0` where there was no status line at all, which
    /// is what a client that could not answer looks like.
    pub status: u16,
    /// The validator to send back on the next request.
    pub etag: Option<String>,
    /// A floor the server asked for, in seconds.
    pub poll_floor: Option<u64>,
    /// Everything past the header block.
    pub body: String,
}

/// Split a raw `-i` response into status, headers and body.
///
/// Carriage returns are dropped first, because a header block arrives CRLF-
/// terminated and a trailing `\r` would ride along inside every value — an
/// `ETag` echoed back with one is not the `ETag` the server issued.
#[must_use]
pub fn parse_response(raw: &str) -> Response {
    let clean = raw.replace('\r', "");
    let mut status = 0u16;
    let mut etag = None;
    let mut poll_floor = None;
    let mut body = String::new();
    let mut in_body = false;

    for (index, line) in clean.split('\n').enumerate() {
        if in_body {
            body.push_str(line);
            body.push('\n');
            continue;
        }
        if line.is_empty() {
            in_body = true;
            continue;
        }
        if index == 0 {
            status = line
                .split_whitespace()
                .nth(1)
                .and_then(|code| code.parse().ok())
                .unwrap_or(0);
            continue;
        }
        if let Some(value) = header(line, "etag") {
            etag = Some(value.to_owned());
        } else if let Some(value) = header(line, "x-poll-interval") {
            poll_floor = value.parse().ok();
        }
    }

    Response {
        status,
        etag,
        poll_floor,
        body,
    }
}

/// The value of `name` on `line`, matched case-insensitively — header names are
/// not case-sensitive and this endpoint has spelled `ETag` both ways.
fn header<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (key, value) = line.split_once(':')?;
    if key.trim().to_ascii_lowercase() == name {
        Some(value.trim())
    } else {
        None
    }
}

/// Project a check-runs document into the rows the decision reads.
///
/// A body that will not parse yields NOTHING rather than an error, which is the
/// same direction the predecessor took: an unreadable reading is "no answer
/// yet", so the poll continues instead of reporting a verdict it never took.
#[must_use]
pub fn runs_from_body(body: &str) -> Vec<Run> {
    let Ok(document) = serde_json::from_str::<serde_json::Value>(body) else {
        return Vec::new();
    };
    let Some(rows) = document.get("check_runs").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    rows.iter()
        .filter_map(|row| {
            let name = row.get("name")?.as_str()?;
            if name.is_empty() {
                return None;
            }
            Some(Run {
                status: string_at(row, "status"),
                // A null conclusion is a run that has not concluded. The
                // placeholder is the predecessor's and it is deliberately not a
                // member of any answered set.
                conclusion: row
                    .get("conclusion")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("-")
                    .to_owned(),
                name: name.to_owned(),
                started_at: string_at(row, "started_at"),
                id: row
                    .get("id")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(0),
            })
        })
        .collect()
}

fn string_at(row: &serde_json::Value, key: &str) -> String {
    row.get(key)
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The interval to honour: the configured one unless the server asked for more.
///
/// A server-sent floor is the endpoint asking to be polled less often, so it
/// wins over the configured interval — but only upward. Reading it as an
/// absolute would let a server that asks for `0` turn this into a spin.
#[must_use]
pub fn interval_for(configured: u64, floor: Option<u64>) -> u64 {
    match floor {
        Some(floor) if floor > configured => floor,
        _ => configured,
    }
}

/// A change detector over a reading, never a digest anyone reads back.
///
/// FNV-1a because the only property needed is that a changed reading changes
/// this, which is what makes "the loop is turning but the world is not" visible.
#[must_use]
pub fn signature(reading: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in reading.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// The state one poll carries into the next.
#[derive(Debug, Default)]
pub struct Poll {
    /// The validator to send with the next request.
    etag: Option<String>,
    /// The last reading that had a body. A `304` leaves this alone.
    runs: Vec<Run>,
    /// How many requests this poll has made.
    polls: u64,
    /// The current reading's signature.
    signature: u64,
    /// The last thing said out loud, so a stall is stated once rather than
    /// every second.
    announced: String,
}

impl Poll {
    /// Fold one raw response in, returning how long to wait before the next
    /// request if the answer is not yet in.
    ///
    /// A `304` is the server saying nothing moved: the previous reading stands
    /// and the signature is not recomputed, because re-hashing an unchanged
    /// string per poll is a cost spent to learn what the status line said.
    pub fn absorb(&mut self, raw: &str, configured: u64) -> u64 {
        self.polls += 1;
        let response = parse_response(raw);
        if let Some(etag) = response.etag {
            self.etag = Some(etag);
        }
        if response.status != 304 {
            self.runs = runs_from_body(&response.body);
            self.signature = signature(&response.body);
        }
        interval_for(configured, response.poll_floor)
    }

    /// The reading this poll currently holds.
    #[must_use]
    pub fn runs(&self) -> &[Run] {
        &self.runs
    }

    /// How many requests have been made.
    #[must_use]
    pub const fn polls(&self) -> u64 {
        self.polls
    }

    /// The current reading's change signature.
    #[must_use]
    pub const fn signature(&self) -> u64 {
        self.signature
    }

    /// Say `line` unless it is what was said last.
    ///
    /// Silence is how a poll that will never resolve looks exactly like one
    /// about to; repeating it every second is how the one that does gets
    /// scrolled away.
    fn announce(&mut self, line: &str, out: &mut dyn Write) -> Result<()> {
        if line.is_empty() || line == self.announced {
            return Ok(());
        }
        writeln!(out, "{line}")?;
        line.clone_into(&mut self.announced);
        Ok(())
    }
}

/// The request this poll makes, as argv.
///
/// Built rather than formatted at the call site so the page size and the
/// conditional header are one object a test can read.
#[must_use]
pub fn request(config: &Config, etag: Option<&str>) -> Vec<String> {
    let mut args = vec![
        String::from("api"),
        String::from("-i"),
        format!(
            "repos/{}/commits/{}/check-runs?per_page={PER_PAGE}",
            config.repo, config.sha
        ),
    ];
    if let Some(etag) = etag {
        args.push(String::from("-H"));
        args.push(format!("If-None-Match: {etag}"));
    }
    args
}

/// Poll until the required checks answer.
///
/// # Errors
///
/// Only for a stream that will not accept output. A roster that cannot decide
/// anything is reported as [`ExitCode::Usage`] before the first request, which
/// is what keeps a config error out of the unbounded loop.
pub fn wait(
    config: &Config,
    roster: &Roster,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // BEFORE THE LOOP, not inside it. An unusable roster is a statement about
    // the invocation, and one polled forever would be a hang whose cause is a
    // typo.
    if let Err(problem) = checks_green::decide(&[], roster) {
        writeln!(err, "::error:: ci wait: {problem}")?;
        return Ok(ExitCode::Usage);
    }

    writeln!(
        out,
        "ci wait: polling check runs for {} (conditional, {}s)",
        config.sha, config.interval
    )?;

    let mut poll = Poll::default();
    loop {
        let raw = read(config, poll.etag.as_deref());
        let wait_for = poll.absorb(&raw, config.interval);
        // EVERY poll pushes, including the ones that learned nothing: proving
        // the loop turned is the tick's whole job.
        push_progress(config, poll.polls(), poll.signature());

        let verdict = match checks_green::decide(poll.runs(), roster) {
            Ok(verdict) => verdict,
            // Unreachable in practice — the roster was proved usable above — but
            // reported rather than unwrapped, because a panic here would end a
            // landing with no verdict at all.
            Err(problem) => {
                writeln!(err, "::error:: ci wait: {problem}")?;
                return Ok(ExitCode::Usage);
            }
        };

        match verdict {
            Verdict::Green => {
                for judged in checks_green::judged(poll.runs(), roster) {
                    writeln!(out, "{judged}")?;
                }
                writeln!(
                    out,
                    "ci wait: every required check terminal and green on {}",
                    config.sha
                )?;
                return Ok(ExitCode::Success);
            }
            Verdict::Red(findings) => {
                for judged in checks_green::judged(poll.runs(), roster) {
                    writeln!(out, "{judged}")?;
                }
                let detail = render(&findings);
                writeln!(
                    err,
                    "::error:: CI is not green on {} — {detail}. Reproduce and fix locally.",
                    config.sha
                )?;
                return Ok(ExitCode::Violation);
            }
            Verdict::Pending(pending) => {
                let line = describe(&pending);
                poll.announce(&line, out)?;
            }
        }

        sleep(wait_for);
    }
}

/// What is being waited on, as the pointer the caller reads.
fn describe(pending: &checks_green::Pending) -> String {
    match pending {
        checks_green::Pending::Running { pending, graded } => {
            format!("ci wait: {pending} required check(s) still running, {graded} graded")
        }
        checks_green::Pending::NoVerdict(findings) => {
            format!(
                "ci wait: required check(s) with no verdict: {}",
                render(findings)
            )
        }
        checks_green::Pending::Unregistered(names) => {
            format!(
                "ci wait: required check(s) with no run at all: {}",
                names.join(", ")
            )
        }
    }
}

fn render(findings: &[checks_green::Finding]) -> String {
    findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// One conditional request, as raw bytes.
///
/// A client that will not answer yields an EMPTY response, never an error: the
/// decision over an empty reading is "no run at all", which is not an answer, so
/// the poll continues. That is the predecessor's posture and the safe one — a
/// transient failure to look must never terminate a wait with a verdict nobody
/// took.
fn read(config: &Config, etag: Option<&str>) -> String {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: reading check runs is a network call and this crate carries no HTTP client, so the forge's own client IS the read (CLOUD-1143)"
    )]
    let output =
        crate::rules::spawn_resolving(Some(std::path::Path::new(".")), CLIENT, |program, extra| {
            std::process::Command::new(program)
                .args(extra)
                .args(request(config, etag))
                .stderr(std::process::Stdio::null())
                .output()
        });
    output.map_or_else(
        |_| String::new(),
        |output| String::from_utf8_lossy(&output.stdout).into_owned(),
    )
}

/// Push both progress signals, ignoring every failure.
fn push_progress(config: &Config, polls: u64, signature: u64) {
    let Some(progress) = config.progress.as_ref() else {
        return;
    };
    record(progress, "tick", &polls.to_string());
    record(progress, "sig", &signature.to_string());
}

fn record(progress: &Progress, signal: &str, value: &str) {
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the recorder is a program the CALLER names, so there is no in-process form of it to prefer — the same standing a handler has (CLOUD-320)"
    )]
    let _ = crate::rules::spawn_resolving(
        Some(std::path::Path::new(".")),
        &progress.program,
        |program, extra| {
            std::process::Command::new(program)
                .args(extra)
                .args([signal, progress.id.as_str(), value])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        },
    );
}

/// The wait between requests. A real sleep, and the only clock in the module.
fn sleep(seconds: u64) {
    if seconds > 0 {
        std::thread::sleep(std::time::Duration::from_secs(seconds));
    }
}

#[cfg(test)]
// Panicking on a failed assertion is how a test fails loudly; these are the
// module's own cases, not a reachable path.
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn roster() -> Roster {
        Roster {
            required: vec![String::from("ci")],
            absent_ok: Vec::new(),
            answered: vec![String::from("success"), String::from("failure")],
            fanin: None,
        }
    }

    fn config() -> Config {
        Config {
            sha: String::from("deadbeef"),
            repo: String::from(REPO_PLACEHOLDER),
            interval: 1,
            progress: None,
        }
    }

    #[test]
    fn a_status_line_and_two_headers_are_read_off_a_raw_response() {
        let parsed =
            parse_response("HTTP/2.0 200 OK\r\nETag: W/\"a\"\r\nX-Poll-Interval: 4\r\n\r\n{}\n");
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.etag.as_deref(), Some("W/\"a\""));
        assert_eq!(parsed.poll_floor, Some(4));
        assert_eq!(parsed.body.trim(), "{}");
    }

    #[test]
    fn a_header_name_is_matched_whatever_its_case() {
        let parsed = parse_response("HTTP/2.0 200 OK\netag: W/\"b\"\nx-poll-interval: 2\n\n{}\n");
        assert_eq!(parsed.etag.as_deref(), Some("W/\"b\""));
        assert_eq!(parsed.poll_floor, Some(2));
    }

    #[test]
    fn a_response_with_no_status_line_is_status_zero_and_an_empty_body() {
        let parsed = parse_response("");
        assert_eq!(parsed.status, 0);
        assert!(parsed.body.trim().is_empty());
    }

    #[test]
    fn a_check_runs_document_projects_to_the_rows_the_decision_reads() {
        let runs = runs_from_body(
            r#"{"check_runs":[{"status":"completed","conclusion":"success","name":"ci","started_at":"2026-08-11T00:00:00Z","id":7}]}"#,
        );
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].name, "ci");
        assert_eq!(runs[0].conclusion, "success");
        assert_eq!(runs[0].started_at, "2026-08-11T00:00:00Z");
        assert_eq!(runs[0].id, 7);
    }

    #[test]
    fn a_null_conclusion_is_not_a_member_of_any_answered_set() {
        let runs = runs_from_body(
            r#"{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}"#,
        );
        assert_eq!(runs[0].conclusion, "-");
        assert!(!roster().answered.contains(&runs[0].conclusion));
    }

    #[test]
    fn a_body_that_will_not_parse_is_no_reading_rather_than_an_error() {
        assert!(runs_from_body("not json").is_empty());
        assert!(runs_from_body("{}").is_empty());
    }

    // THE 304 CASE, and it is the reason the reading is state rather than a
    // local. Re-parsing an absent body as an empty check set restarts the wait
    // on every unchanged poll.
    #[test]
    fn a_304_keeps_the_previous_reading_instead_of_clearing_it() {
        let mut poll = Poll::default();
        poll.absorb(
            "HTTP/2.0 200 OK\nETag: W/\"a\"\n\n{\"check_runs\":[{\"status\":\"completed\",\"conclusion\":\"success\",\"name\":\"ci\"}]}\n",
            1,
        );
        let before = poll.signature();
        assert_eq!(poll.runs().len(), 1);

        poll.absorb("HTTP/2.0 304 Not Modified\nETag: W/\"a\"\n\n", 1);
        assert_eq!(poll.runs().len(), 1, "a 304 must not clear the reading");
        assert_eq!(
            poll.signature(),
            before,
            "a 304 is the server saying nothing moved, so the signature must not move either"
        );
        assert_eq!(poll.polls(), 2, "a 304 is still a poll that turned");
    }

    #[test]
    fn a_reading_that_changes_moves_the_signature() {
        let mut poll = Poll::default();
        poll.absorb(
            "HTTP/2.0 200 OK\n\n{\"check_runs\":[{\"status\":\"in_progress\",\"conclusion\":null,\"name\":\"ci\"}]}\n",
            1,
        );
        let before = poll.signature();
        poll.absorb(
            "HTTP/2.0 200 OK\n\n{\"check_runs\":[{\"status\":\"completed\",\"conclusion\":\"success\",\"name\":\"ci\"}]}\n",
            1,
        );
        assert_ne!(poll.signature(), before);
    }

    #[test]
    fn an_etag_survives_a_response_that_carries_none() {
        let mut poll = Poll::default();
        poll.absorb("HTTP/2.0 200 OK\nETag: W/\"a\"\n\n{}\n", 1);
        poll.absorb("HTTP/2.0 200 OK\n\n{}\n", 1);
        assert_eq!(poll.etag.as_deref(), Some("W/\"a\""));
    }

    #[test]
    fn a_server_requested_floor_is_honoured_over_a_shorter_interval() {
        assert_eq!(interval_for(1, Some(3)), 3);
    }

    // ...and only upward. A floor read as an absolute would let a server asking
    // for `0` turn an affordable poll into a spin.
    #[test]
    fn a_server_floor_below_the_configured_interval_does_not_lower_it() {
        assert_eq!(interval_for(5, Some(1)), 5);
        assert_eq!(interval_for(5, Some(0)), 5);
        assert_eq!(interval_for(5, None), 5);
    }

    // The request IS part of the predicate (CLOUD-337): this endpoint returns a
    // run per event per name, and nothing here fetches page 2.
    #[test]
    fn the_request_asks_for_a_full_page() {
        let args = request(&config(), None);
        assert!(
            args.iter().any(|arg| arg.contains("per_page=100")),
            "{args:?}"
        );
    }

    #[test]
    fn a_held_etag_becomes_a_conditional_header_and_nothing_else_moves() {
        let plain = request(&config(), None);
        let conditional = request(&config(), Some("W/\"a\""));
        assert_eq!(conditional.len(), plain.len() + 2);
        assert!(conditional.contains(&String::from("If-None-Match: W/\"a\"")));
    }

    #[test]
    fn an_unusable_roster_exits_usage_before_a_single_request() {
        let empty = Roster {
            required: Vec::new(),
            absent_ok: Vec::new(),
            answered: vec![String::from("success")],
            fanin: None,
        };
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = wait(&config(), &empty, &mut out, &mut err).expect("write");
        assert_eq!(code, ExitCode::Usage);
        assert!(
            out.is_empty(),
            "a refused roster must not announce a poll it never starts"
        );
        assert!(String::from_utf8_lossy(&err).contains("every check would be unrequired"));
    }

    #[test]
    fn a_stall_is_stated_once_rather_than_every_poll() {
        let mut poll = Poll::default();
        let mut out = Vec::new();
        poll.announce("still running", &mut out).expect("write");
        poll.announce("still running", &mut out).expect("write");
        poll.announce("now something else", &mut out)
            .expect("write");
        assert_eq!(
            String::from_utf8_lossy(&out),
            "still running\nnow something else\n"
        );
    }
}
