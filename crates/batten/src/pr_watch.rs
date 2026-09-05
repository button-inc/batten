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

/// How long to wait before the next request, honouring BOTH server bounds.
///
/// **THE BACKOFF DOES NOT GO THROUGH `interval_for`, AND ROUTING IT THERE WAS A
/// DEFECT** (review of #848). The two are different things and `rest.rs` says so
/// at the field: `poll_floor` is *how often to ask*, `backoff` is *stop asking
/// until*. `MAX_FLOOR` is a ceiling on the first — its own doc justifies it
/// purely as a guard on `X-Poll-Interval`, "larger than any interval this forge
/// has been observed to ask for, so it clamps nothing real" — and it is
/// meaningless as a ceiling on the second.
///
/// Measured consequence of conflating them: `rest::backoff_of` resolves
/// `x-ratelimit-reset - now` once `x-ratelimit-remaining` is `0`, so a primary
/// limit resetting fifty minutes out yields `3000`. Clamped to `300`, the poll
/// waits five minutes and re-issues the same request, ten more times, each
/// answered `403` — which is verbatim the "responding to being rate-limited by
/// generating more of the request that had just been refused" behaviour
/// `Answer::backoff` was added to stop.
///
/// So the cadence is clamped and the backoff is not, and the answer is whichever
/// is longer: a backoff is a lower bound on the wait exactly as a floor is, and
/// satisfying only one of them satisfies neither.
#[must_use]
pub(crate) fn wait_for(configured: u64, floor: Option<f64>, backoff: Option<u64>) -> f64 {
    let paced = interval_for(configured, floor);
    // Narrowed the way `interval_for` narrows its own argument, and for the same
    // reason: the conversion is exact for every value that survives it.
    let backoff = backoff.map_or(0.0, |secs| {
        f64::from(u32::try_from(secs).unwrap_or(u32::MAX))
    });
    paced.max(backoff)
}

/// The interval to honour: the configured one unless the server asked for more.
///
/// A server-sent floor is the endpoint asking to be polled less often, so it
/// wins over the configured interval — but only upward. Reading it as an
/// absolute would let a server that asks for `0` turn this into a spin.
/// **The comparison is NUMERIC.** An integer one is what CLOUD-390 removed from
/// the predecessor, and restoring it here would drop any fractional floor the
/// endpoint sends — the same silent hole, in a different language.
///
/// **LOSSLESS BY CONSTRUCTION rather than by annotation** (CLOUD-1338). This
/// carried an `#[expect(clippy::cast_precision_loss)]` over `configured as f64`,
/// whose reason argued the value is always small — which is a claim about
/// callers, checked by nobody. Narrowing to `u32` first makes the conversion
/// exact for every value that survives it, and saturating states the bound in
/// code: `u32::MAX` seconds is 136 years, so a poll interval that reached it was
/// never going to turn again anyway.
#[must_use]
pub fn interval_for(configured: u64, floor: Option<f64>) -> f64 {
    let configured = f64::from(u32::try_from(configured).unwrap_or(u32::MAX));
    match floor {
        // FINITE OR IT IS NOT A FLOOR, and the guard belongs HERE rather than
        // only at the boundary that parses one. `crate::rest` already filters a
        // header to a finite positive, so nothing unusable arrives from the real
        // path today — but this function is public and takes an `f64`, so a
        // caller constructing one reaches it, and `INFINITY > configured` holds:
        // the answer would be an infinite wait, which is the hang the
        // predecessor's `+0` coercion existed to refuse. A floor nobody can
        // satisfy is no floor.
        // AND THE CEILING NEVER REDUCES THE CONFIGURED INTERVAL. `MAX_FLOOR` is a
        // bound on what the SERVER may add, not a bound on what the caller asked
        // for: with `configured` above it, a raw `min(MAX_FLOOR)` answered BELOW
        // the interval this poll was told to use — the one direction this
        // function must never take, since `Config::interval` is the caller's
        // floor and nothing here is entitled to lower it.
        Some(floor) if floor.is_finite() && floor > configured => {
            floor.min(MAX_FLOOR.max(configured))
        }
        _ => configured,
    }
}

/// The longest interval a server may ask this poll to wait, in seconds.
///
/// **A CEILING, because the floor comes off the wire.** `X-Poll-Interval` is a
/// number the forge sends, and a finite one is not thereby a reasonable one: an
/// endpoint answering `86400` — or a proxy inventing one — turns a wait into a
/// hang that looks exactly like a slow bot. The finiteness guard above stops the
/// infinity; this stops the merely absurd.
///
/// Five minutes, against a poll whose own default is one second and a landing
/// whose bound is a COUNT rather than a clock: honouring a floor this large
/// already means the lap spends its whole ask budget on a handful of requests,
/// which is the signal a reader needs. Larger than any interval this forge has
/// been observed to ask for, so it clamps nothing real.
const MAX_FLOOR: f64 = 300.0;

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
    /// The last backoff the SERVER asked for, held across a poll that could not
    /// look.
    ///
    /// **A `Retry-After` must outlive one transport failure** (review of #848).
    /// `absorb`'s could-not-look arm recomputed the wait from the response alone,
    /// and a `None` response has none — so a `403` carrying `Retry-After: 300`
    /// was honoured once, and the very next reset connection dropped the wait
    /// back to the configured cadence and resumed hammering for the rest of the
    /// rate-limit window. That is exactly the behaviour `Answer::backoff` exists
    /// to stop, reintroduced by the arm that has no answer to read it from.
    ///
    /// Cleared by a real reading, because a `200` is the server saying the window
    /// is over — holding it past that would be a second authority over a cadence
    /// the endpoint already answers for.
    backoff: Option<u64>,
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
    /// **`None` is a poll that could not look**, and it is folded rather than
    /// skipped: the count still advances, the previous reading still stands, and
    /// the caller waits its configured interval. Dropping it would let an
    /// unreachable forge make a bounded loop unbounded — the same fold
    /// [`crate::main_watch::Poll::absorb`] makes, and deliberately the same
    /// shape, since the two are the arms of one race.
    pub fn absorb(&mut self, answer: Option<&crate::rest::Answer>, configured: u64) -> f64 {
        self.polls += 1;
        let Some(answer) = answer else {
            // The server's last word stands: a poll that could not look learned
            // nothing that would retire it.
            return wait_for(configured, None, self.backoff);
        };
        // AN ETAG SURVIVES A RESPONSE THAT CARRIES NONE, which is what keeps a
        // single unvalidated answer from turning every later request
        // unconditional.
        if let Some(etag) = &answer.etag {
            self.etag = Some(etag.clone());
        }
        // **ONLY A READING REPLACES THE READING** (review of #848). This was
        // `status != 304`, which takes every OTHER status too — so a `401`, a
        // `403` or a `404` had its ERROR DOCUMENT parsed as a check-run page,
        // yielding zero runs, and that empty set overwrote a good reading. The
        // trap is what follows: an error response carries no `ETag`, so the
        // previous validator survives the branch above, the next request is
        // conditional against it, the forge answers `304`, and the empty reading
        // is then preserved by the very rule that exists to preserve a good one.
        // One transient error and the poll holds "no runs" indefinitely.
        //
        // `is_reading()` is `200` alone, and `304` is deliberately not one: it
        // means *nothing changed*, so the reading it refers to is the one already
        // held. The guard was applied at `head_verdict` and not here, where every
        // poll actually goes through.
        if answer.is_reading() {
            self.runs = runs_from_body(&answer.body);
            self.signature = signature(&answer.body);
        }
        // A reading retires the window; anything else may extend it.
        self.backoff = if answer.is_reading() {
            None
        } else {
            answer.backoff.or(self.backoff)
        };
        // THE SERVER'S BACKOFF OUTRANKS THE CONFIGURED FLOOR. `Answer::backoff`
        // carries `Retry-After`, and it had no consumer at all — a `403` that
        // said "wait 60 seconds" was answered by continuing at the configured
        // 1s cadence, which is the predecessor defect `rest.rs` names as the
        // reason the field exists.
        wait_for(configured, answer.poll_floor, answer.backoff)
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

    /// The validator to send with the next request, where the server issued one.
    ///
    /// Exposed for a caller driving ONE poll at a time rather than [`watch`]'s
    /// loop — `land`'s lap alternates this question with a second one, so it
    /// carries the poll state across iterations itself. Without this the
    /// conditional half is unreachable outside the module and every poll would
    /// be unconditional, which is what makes the 1s interval affordable at all.
    #[must_use]
    pub fn etag(&self) -> Option<&str> {
        self.etag.as_deref()
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

/// Poll until the required checks answer.
///
/// # Errors
///
/// Only for a stream that will not accept output. A roster that cannot decide
/// anything is reported as [`ExitCode::Usage`] before the first request, which
/// is what keeps a config error out of the unbounded loop.
pub fn watch(
    config: &Config,
    roster: &Roster,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // BEFORE THE LOOP, not inside it. An unusable roster is a statement about
    // the invocation, and one polled forever would be a hang whose cause is a
    // typo.
    if let Err(problem) = checks_green::decide(&[], roster) {
        writeln!(err, "::error:: pr watch: {problem}")?;
        return Ok(ExitCode::Usage);
    }

    writeln!(
        out,
        "pr watch: polling check runs for {} (conditional, {}s)",
        config.sha, config.interval
    )?;

    let mut poll = Poll::default();
    loop {
        let raw = read(config, poll.etag.as_deref());
        let wait_for = poll.absorb(raw.as_ref(), config.interval);
        // EVERY poll pushes, including the ones that learned nothing: proving
        // the loop turned is the tick's whole job.
        push_progress(config, poll.polls(), poll.signature());

        let verdict = match checks_green::decide(poll.runs(), roster) {
            Ok(verdict) => verdict,
            // Unreachable in practice — the roster was proved usable above — but
            // reported rather than unwrapped, because a panic here would end a
            // landing with no verdict at all.
            Err(problem) => {
                writeln!(err, "::error:: pr watch: {problem}")?;
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
                    "pr watch: every required check terminal and green on {}",
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
            format!("pr watch: {pending} required check(s) still running, {graded} graded")
        }
        checks_green::Pending::NoVerdict(findings) => {
            format!(
                "pr watch: required check(s) with no verdict: {}",
                render(findings)
            )
        }
        checks_green::Pending::Unregistered(names) => {
            format!(
                "pr watch: required check(s) with no run at all: {}",
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
/// One conditional read of the check runs, as raw response bytes.
///
/// PUBLIC SO THERE IS ONE READER RATHER THAN TWO (CLOUD-1338). `land`'s lap asks
/// this question alternately with a staleness one, so it cannot use [`watch`]'s
/// loop — and a lap that spawned the forge client itself would be a second
/// authority over the request, the argv and the failure posture. The loop is the
/// caller's; the read stays here.
///
/// An answer that could not be taken is `None`, never an error: every failure to
/// reach the forge is a could-not-look that the caller's own poll must survive.
///
/// # THE SPAWN IS GONE, AND THE REASON IT CARRIED WAS FALSE
///
/// This read was a `gh api -i` child process under
/// `#[expect(clippy::disallowed_types)]` with the reason *"this crate carries no
/// HTTP client, so the forge's own client IS the read"*. It does —
/// [`crate::fetch`] is a vendored hyper client and [`crate::rest`] is the tier
/// over it, both already in the crate — so the annotation recorded a decision
/// nobody had the facts for. It is [`crate::rest::get`] now, the same one
/// [`crate::main_watch::read`] takes, which is what makes the two arms of a lap's
/// race one client rather than two.
///
/// The header parsing went with it. `-i` handed back a raw response that this
/// module then parsed itself for the status, the `ETag` and `X-Poll-Interval` —
/// a second header parser beside [`crate::rest::Answer`]'s, which is exactly the
/// second authority that split does not survive.
#[must_use]
pub fn read(config: &Config, etag: Option<&str>) -> Option<crate::rest::Answer> {
    crate::rest::get(
        &format!(
            "repos/{}/commits/{}/check-runs?per_page={PER_PAGE}",
            config.repo, config.sha
        ),
        etag,
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

/// The recorder's argv: the program, then the words that precede the signal.
///
/// **A recorder may be a VERB rather than a program** (CLOUD-1170). The retiring
/// `mise-tasks/task-registry.sh` was one file, so the whole recorder was one
/// word; its successor is `batten task`, and `spawn_resolving` resolves a program
/// NAME rather than a command line — handed `"batten task"` it would look for a
/// file called `batten task`, fail, and be swallowed by the ignore-every-failure
/// posture below. Silent, and exactly the capability loss this signal exists to
/// prevent.
///
/// Split on whitespace, and that is the whole of the parsing: this is a config
/// value a consumer writes, never a shell line, so there is no quoting to honour
/// and pretending otherwise would be the second parser CLOUD-857 measured. A
/// recorder whose path contains a space needs a wrapper, and that bound is
/// stated rather than discovered.
fn recorder_argv(program: &str) -> (&str, Vec<&str>) {
    let mut words = program.split_whitespace();
    (words.next().unwrap_or(program), words.collect())
}

fn record(progress: &Progress, signal: &str, value: &str) {
    let (program, leading) = recorder_argv(&progress.program);
    #[expect(
        clippy::disallowed_types,
        reason = "stays: the recorder is a program the CALLER names, so there is no in-process form of it to prefer — the same standing a handler has (CLOUD-320)"
    )]
    let _ = crate::rules::spawn_resolving(
        Some(std::path::Path::new(".")),
        program,
        |program, extra| {
            std::process::Command::new(program)
                .args(extra)
                .args(&leading)
                .args([signal, progress.id.as_str(), value])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
        },
    );
}

/// The wait between requests. A real sleep, and the only clock in the module.
///
/// PUBLIC FOR THE SAME REASON [`read`] IS (CLOUD-1338): a caller driving one
/// poll at a time needs the interval the server asked for, and re-deriving the
/// pause at the call site would put a second clock in the crate — the one thing
/// `clippy.toml`'s timer ban exists to keep out. Named `pause` rather than
/// `sleep` on the public surface because what a caller is asking for is the
/// interval BETWEEN asks, not a duration of its own choosing.
pub fn pause(seconds: f64) {
    sleep(seconds);
}

/// The longest a raced arm sleeps before it re-reads the stop flag.
///
/// Not a second interval — the wait is still the server's, and this only bounds
/// how coarsely it is served. One second because that is the poll's own default
/// cadence, so an arm that is NOT stopped behaves exactly as it did.
const STOP_CHECK_SLICE: f64 = 1.0;

/// [`pause`], abandoned early when `stop` is raised.
///
/// **THE LOSER OF A RACE HELD THE WHOLE WAIT** (review of #848). Both arms of
/// `land::wait` check their stop flag at the top of the loop and then sleep the
/// full interval, and `thread::scope` joins them before the verdict can be acted
/// on — so a green answer sat unused for as long as the loser's last interval.
/// That was survivable while the interval was the poll's one second. It stopped
/// being survivable when `wait_for` started honouring a rate-limit backoff, which
/// is measured in minutes: the arm that lost would hold a finished landing for
/// the whole of somebody else's `Retry-After`.
///
/// **One clock still, which is the constraint that shapes this.** `clippy.toml`
/// bans timers precisely so a second arm cannot grow one, and the crate's single
/// exemption lives on [`sleep`] below. So this does not add a wait — it serves
/// the same one in slices, checking between them. An arm that is never stopped
/// sleeps the identical total.
pub fn pause_until(seconds: f64, stop: &std::sync::atomic::AtomicBool) {
    if !seconds.is_finite() || seconds <= 0.0 {
        return;
    }
    let mut left = seconds;
    while left > 0.0 {
        if stop.load(std::sync::atomic::Ordering::Relaxed) {
            return;
        }
        let slice = left.min(STOP_CHECK_SLICE);
        sleep(slice);
        left -= slice;
    }
}

fn sleep(seconds: f64) {
    if seconds > 0.0 && seconds.is_finite() {
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval between conditional requests, and the interval is the SERVER'S: \
                      `interval_for` raises it to whatever `X-Poll-Interval` asked for and never \
                      lowers it. The loop exits on the required set reaching a verdict — \
                      `Verdict::Green` or `Verdict::Red` both return — never on a clock \
                      (CLOUD-1177)"
        )]
        std::thread::sleep(std::time::Duration::from_secs_f64(seconds));
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

    /// One answer, as `rest::get` hands it back.
    ///
    /// **THE HEADERS ARE ALREADY OFF IT, which is the point of the port.** These
    /// cases used to build a raw `-i` response and drive this module's own header
    /// parser; that parser is gone, and `crate::rest::Answer` is the one reading
    /// of a status, an `ETag` and a poll floor in this crate.
    fn answer(status: u16, etag: Option<&str>, body: &str) -> crate::rest::Answer {
        crate::rest::Answer {
            status,
            etag: etag.map(str::to_owned),
            poll_floor: None,
            backoff: None,
            body: body.to_owned(),
        }
    }

    /// **A POLL THAT COULD NOT LOOK IS FOLDED, NEVER SKIPPED.** The count still
    /// advances and the previous reading still stands, which is what keeps an
    /// unreachable forge from making a bounded loop unbounded — the arm the raw
    /// empty string used to spell, now typed.
    #[test]
    fn a_poll_that_could_not_look_keeps_the_reading_and_still_counts() {
        let mut poll = Poll::default();
        poll.absorb(
            Some(&answer(
                200,
                Some("W/\"a\""),
                r#"{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}"#,
            )),
            1,
        );
        assert_eq!(poll.runs().len(), 1);

        poll.absorb(None, 1);
        assert_eq!(
            poll.runs().len(),
            1,
            "a reading nobody took must not clear the one that stands"
        );
        assert_eq!(poll.polls(), 2, "and it is still a poll that turned");
        assert_eq!(
            poll.etag(),
            Some("W/\"a\""),
            "nor may it drop the validator, which would turn every later request unconditional"
        );
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
            Some(&answer(
                200,
                Some("W/\"a\""),
                r#"{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}"#,
            )),
            1,
        );
        let before = poll.signature();
        assert_eq!(poll.runs().len(), 1);

        poll.absorb(Some(&answer(304, Some("W/\"a\""), "")), 1);
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
            Some(&answer(
                200,
                None,
                r#"{"check_runs":[{"status":"in_progress","conclusion":null,"name":"ci"}]}"#,
            )),
            1,
        );
        let before = poll.signature();
        poll.absorb(
            Some(&answer(
                200,
                None,
                r#"{"check_runs":[{"status":"completed","conclusion":"success","name":"ci"}]}"#,
            )),
            1,
        );
        assert_ne!(poll.signature(), before);
    }

    #[test]
    fn an_etag_survives_a_response_that_carries_none() {
        let mut poll = Poll::default();
        poll.absorb(Some(&answer(200, Some("W/\"a\""), "{}")), 1);
        poll.absorb(Some(&answer(200, None, "{}")), 1);
        assert_eq!(poll.etag.as_deref(), Some("W/\"a\""));
    }

    /// Seconds, compared to a tolerance rather than for bit equality — the
    /// interval became numeric with CLOUD-390's fix and a strict `==` over `f64`
    /// is a lint this crate denies for the ordinary reason.
    fn is(seconds: f64, expected: f64) -> bool {
        (seconds - expected).abs() < f64::EPSILON
    }

    #[test]
    fn a_server_requested_floor_is_honoured_over_a_shorter_interval() {
        assert!(is(interval_for(1, Some(3.0)), 3.0));
    }

    /// **A FRACTIONAL FLOOR IS A FLOOR, and this is CLOUD-390 held at its own
    /// layer.** The predecessor compared with `-gt`, which is integer-only, so a
    /// fractional `X-Poll-Interval` read as "no floor asked for". The first Rust
    /// port reproduced it: `poll_floor` was `Option<u64>`, and `"2.5".parse()`
    /// yields `None` — byte-identical to an absent header.
    #[test]
    fn a_fractional_server_floor_is_not_silently_dropped() {
        assert!(is(interval_for(1, Some(2.5)), 2.5));
        assert!(is(interval_for(1, Some(0.5)), 1.0), "and only upward");
    }

    // ...and only upward. A floor read as an absolute would let a server asking
    // for `0` turn an affordable poll into a spin.
    #[test]
    fn a_server_floor_below_the_configured_interval_does_not_lower_it() {
        assert!(is(interval_for(5, Some(1.0)), 5.0));
        assert!(is(interval_for(5, Some(0.0)), 5.0));
        assert!(is(interval_for(5, None), 5.0));
    }

    /// A floor nobody can compare must not become one nobody can satisfy: `NaN`
    /// loses every comparison and an infinity wins every one, so both read as no
    /// floor at all — the fail-open direction the predecessor's `+0` coercion
    /// took.
    ///
    /// **The PARSE half of this case is `crate::rest`'s now**, and moving it is
    /// what found the defect this case now pins. `exchange` filters a header to a
    /// finite positive, so nothing unusable arrives from the real path — and
    /// `interval_for` did not guard it at all, so `INFINITY > configured` held
    /// and the answer was an infinite wait. The boundary's filter was the only
    /// thing standing between a public `f64` parameter and a hang.
    #[test]
    fn a_non_finite_floor_reads_as_no_floor_rather_than_as_a_hang() {
        assert!(is(interval_for(5, Some(f64::NAN)), 5.0));
        assert!(is(interval_for(5, Some(f64::INFINITY)), 5.0));
        assert!(is(interval_for(5, Some(-1.0)), 5.0));
    }

    /// **AND A FINITE FLOOR IS NOT THEREBY A REASONABLE ONE.** The value comes
    /// off the wire, so an endpoint answering a day — or a proxy inventing one —
    /// would turn this wait into a hang indistinguishable from a slow bot. The
    /// pair: at the ceiling the floor is honoured exactly, above it clamps.
    #[test]
    fn a_floor_beyond_the_ceiling_is_clamped_and_one_at_it_is_honoured() {
        assert!(is(interval_for(1, Some(MAX_FLOOR)), MAX_FLOOR));
        assert!(is(interval_for(1, Some(MAX_FLOOR * 100.0)), MAX_FLOOR));

        // AND THE CEILING NEVER CUTS BELOW WHAT THE CALLER CONFIGURED. With an
        // interval above `MAX_FLOOR`, a raw `min` answered 300 for a poll told
        // to wait 600 — the ceiling reducing the caller's own floor, which is
        // the one direction this function may never take. Found in review.
        assert!(
            is(interval_for(600, Some(700.0)), 600.0),
            "a configured interval above the ceiling is never reduced by it"
        );
        assert!(
            is(interval_for(600, None), 600.0),
            "and the same interval with no floor at all is unchanged"
        );
        // And an ordinary floor is untouched, so the clamp discriminates.
        assert!(is(interval_for(1, Some(4.0)), 4.0));
    }

    // The request IS part of the predicate (CLOUD-337): this endpoint returns a
    // run per event per name, and nothing here fetches page 2.
    #[test]
    fn the_request_asks_for_a_full_page() {
        assert_eq!(PER_PAGE, 100);
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
        let code = watch(&config(), &empty, &mut out, &mut err).expect("write");
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
