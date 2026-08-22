//! The `[[hook.handler]]` dispatch surface (CLOUD-898) — one door to the
//! hooking surface, and one contract behind it.
//!
//! A **handler** is a declared program that *participates* in the hook contract:
//! Batten runs it for an event, bounds it, reads its exit code and streams under
//! a stated contract, and merges the result into the one reply the host reads.
//! It is what lets `batten hook` be the only registration on every surface while
//! a repository still runs whatever it likes behind it.
//!
//! ## Why this is not [`crate::action`]
//!
//! [`crate::action`] already spawns a declared command on an event, and cannot
//! serve here. Its module doc states three properties as deliberate, and every
//! one of them is exactly wrong for a handler:
//!
//! * `fire` returns `()`, and "an action can never change the answer" is called
//!   the load-bearing property — structural rather than promised.
//! * the child's streams are **discarded**, so nothing it says reaches anyone.
//! * `pre-tool` is **refused** outright.
//!
//! Those are the right properties for a side effect and the wrong ones for a
//! participant. So `action` keeps its guarantee unchanged and this is a second
//! noun: two kinds, two contracts, neither weakened to accommodate the other. A
//! reader choosing between them has one question — *may this change the answer?*
//! — and the kind is the answer.
//!
//! ## `pre-tool` is admitted here, and not by symmetry
//!
//! `action` refuses it for two independent reasons. The **first does not
//! transfer**: a side effect at `pre-tool` runs before a possible deny, which
//! inverts what a mediated gate is for — but a handler *is* part of that
//! decision rather than something happening alongside it, so there is no
//! ordering to invert. It is the event a handler most needs.
//!
//! The **second transfers intact** and is honoured rather than argued away:
//! `run_hook`'s hot path deliberately touches no config when a pre-tool payload
//! carries neither a command nor a write, and a handler table read at that point
//! would put a config load back on the most frequent call in the binary. So
//! [`selects`] is the narrowing, in CLOUD-460's shape — the same one
//! `reads_prospective` uses. A call no handler selects for does less work than
//! `--help`, and that is asserted rather than intended.
//!
//! ## The contract, which is the whole point of the door
//!
//! Four things Batten enforces that no dispatched program can enforce for
//! itself. Every one was previously re-derived, differently, in each registered
//! script:
//!
//! 1. **A bound.** [`Handler::timeout`] is imposed by the parent, so a handler
//!    that hangs cannot wedge a turn. `stop-guard` hand-rolled `timeout 1s cat`
//!    for exactly this and said so in a comment; the rest had no bound at all.
//! 2. **Fail-open, centrally.** A spawn that fails, a handler that times out, an
//!    exit code outside the contract — all of them are *could not look*, which
//!    allows. Each script used to spell this in its own error paths, and a
//!    missed one was a hook that could refuse because it was broken.
//! 3. **A stated output shape.** stdout on a passing exit is advisory text; a
//!    refusal's reason travels on stderr. Anything else is a **contract
//!    violation**, reported and never forwarded. This is also what makes
//!    "a hook must not announce success" (CLOUD-891) a property of the surface
//!    rather than a habit each script is trusted to keep.
//! 4. **One reply per call.** The host reads a single document, so handler
//!    results merge rather than each speaking. [`Dispatched`] is that merge.
//!
//! ### stdout is *interpreted*, never forwarded
//!
//! This is the rule-4 answer and the portability answer at once, and it is the
//! difference between this and registering the script directly.
//!
//! [`crate::action`] must discard its child's streams because user-supplied
//! output is the likeliest place for a secret to surface. A handler's output
//! cannot be discarded — it *is* the channel — so it is read into Batten's own
//! types instead, and Batten re-renders per harness. A handler therefore speaks
//! to *Batten*, in Batten's vocabulary, and never to the host: it cannot emit a
//! host decision document, because nothing forwards one. That is what makes a
//! repository's hooks behave the same on every harness rather than on the one
//! whose JSON its author happened to write.
//!
//! A handler that tries anyway is reported as [`Violation::ImpersonatedHost`]
//! rather than passed along — named rather than dropped, because a silently
//! discarded document is an author who believes they are deciding something.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
#[expect(
    clippy::disallowed_types,
    reason = "stays: a handler IS a program the operator declared in `[[hook.handler]]`, so there is no in-process form of it to prefer — the same standing `action` has (CLOUD-320)"
)]
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::hook::Event;

/// The exit code a handler refuses with.
///
/// §7's table, unchanged and with no per-kind exception: `2` is the policy
/// verdict everywhere in this engine, so a handler refuses with the same code a
/// rule does and a reader needs one table rather than two.
pub const DENY_EXIT: i32 = 2;

/// The exit code a handler reports its own finding with.
///
/// §7 again: `1` is "the thing you asked about is wrong". A handler exiting `1`
/// has found a problem it is not refusing over — the same distinction `check`
/// draws between a violation and a policy deny.
pub const VIOLATION_EXIT: i32 = 1;

/// How long a handler may run before the parent kills it, absent its own bound.
///
/// Five seconds, chosen against the surface rather than picked: the measured
/// registrations this replaces run in tens of milliseconds — `stop-guard` at
/// ~28ms by path, the pre-tool guards at ~11ms of policy — so this is two orders
/// of magnitude of headroom. Generous enough that no honest handler meets it,
/// tight enough that a hung one does not hold a turn open. A handler that
/// genuinely needs longer says so; what it may not do is decline to have a bound.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// How often the parent checks whether a bounded handler has exited.
///
/// A poll rather than a blocking wait with a deadline, because the standard
/// library offers no timed wait and the alternative is a reaper thread per
/// handler. Ten milliseconds is below the resolution anything here reports, and
/// costs one syscall per tick against a child that is usually already gone.
const POLL: Duration = Duration::from_millis(10);

/// One declared handler.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Handler {
    /// The stable identifier a verdict, a violation and a timing are reported
    /// under.
    ///
    /// Separate from the command for [`crate::action::Action`]'s reason: the
    /// argv is free to change without the thing it is called in reports changing
    /// with it. Here it carries a second load — it is the key a per-handler
    /// timing series is recorded against, so a renamed handler starts a new
    /// series rather than silently continuing another's.
    pub id: String,
    /// The event this handler runs on, as [`Event::as_str`] spells it.
    ///
    /// A **normalized** token, never a host's own word — `action`'s rule for
    /// `action`'s reason: a handler declared once should run on every host that
    /// offers the moment, and keying it on one host's spelling would silently
    /// not run on another's.
    pub on: String,
    /// The command, as argv. Never a shell string.
    ///
    /// argv rather than a command line so there is no quoting layer between what
    /// an operator wrote and what runs: no word splitting, no glob expansion, no
    /// command substitution.
    pub run: Vec<String>,
    /// How long this handler may run, in milliseconds.
    ///
    /// Absent means [`DEFAULT_TIMEOUT`]. There is deliberately no spelling for
    /// "no timeout": the bound is the property the door exists to provide, and a
    /// surface letting a handler opt out of it would return every registration
    /// to the state this replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl Handler {
    /// The event this handler names, or `None` when `on` names none.
    #[must_use]
    pub fn event(&self) -> Option<Event> {
        event_of(&self.on)
    }

    /// The bound this handler runs under.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout_ms
            .map_or(DEFAULT_TIMEOUT, Duration::from_millis)
    }

    /// Reject a handler that cannot honestly run.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `id`, an `on` naming
    /// no known event or naming `unrecognized`, an empty `run`, a `run` whose
    /// program is empty, or a zero timeout.
    fn validate(&self) -> anyhow::Result<()> {
        if self.id.is_empty() {
            return Err(UsageError::raise("hook.handler: `id` must not be empty"));
        }
        let Some(event) = self.event() else {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `on` names no event ({:?}); expected one of {}",
                self.id,
                self.on,
                declarable_tokens().join(", ")
            )));
        };
        // Not a moment, but the absence of one Batten could name — `action`'s
        // refusal verbatim, for the same reason. A handler keyed here would run
        // on any host event this build has never heard of: the widest possible
        // trigger, chosen by nobody.
        if event == Event::Unrecognized {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `on` may not be {:?} — it names no moment, only that the host \
                 said a word this build does not know",
                self.id,
                Event::Unrecognized.as_str()
            )));
        }
        let Some(program) = self.run.first() else {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `run` must name a command",
                self.id
            )));
        };
        if program.is_empty() {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `run`'s first element is the program and must not be empty",
                self.id
            )));
        }
        // A zero bound is not "no bound", it is a handler that can never
        // succeed. Refusing it at load is the difference between an author
        // learning this now and a turn losing every handler to a timeout later.
        if self.timeout_ms == Some(0) {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `timeout_ms` must be greater than zero",
                self.id
            )));
        }
        Ok(())
    }
}

/// Every event token a handler may name.
///
/// Derived from [`Event::ALL`] rather than re-typed, so an event added to the
/// enum becomes declarable in the same change instead of in a forgotten second
/// table. `pre-tool` IS among them — see the module docs for why it is here and
/// absent from `action`'s list.
#[must_use]
pub fn declarable_tokens() -> Vec<&'static str> {
    Event::ALL
        .iter()
        .filter(|event| **event != Event::Unrecognized)
        .map(|event| event.as_str())
        .collect()
}

/// The event a token names, if any.
fn event_of(token: &str) -> Option<Event> {
    Event::ALL
        .iter()
        .copied()
        .find(|event| event.as_str() == token)
}

/// Reject a handler set that cannot honestly run.
///
/// # Errors
///
/// Propagates the first row's validation failure, and raises on a duplicate
/// `id` — ids identify a row in its reports, and two rows sharing one would make
/// a timing series and a violation ambiguous.
pub fn validate(handlers: &[Handler]) -> anyhow::Result<()> {
    let mut seen = BTreeSet::new();
    for handler in handlers {
        handler.validate()?;
        if !seen.insert(handler.id.as_str()) {
            return Err(UsageError::raise(format!(
                "hook.handler {}: declared twice; ids identify a row in its reports",
                handler.id
            )));
        }
    }
    Ok(())
}

/// Whether any declared handler runs at `event`.
///
/// **The narrowing, and the reason `pre-tool` is affordable** (CLOUD-460). A
/// repository declaring no handler for the event pays one slice scan and nothing
/// else — no spawn, no pipe, no read. Called before any work, so the hot path
/// stays what §4 promises: cheap when irrelevant.
#[must_use]
pub fn selects(handlers: &[Handler], event: Event) -> bool {
    handlers
        .iter()
        .any(|handler| handler.event() == Some(event))
}

/// Why a handler's answer could not be taken at face value.
///
/// Every variant **allows**. A handler that broke the contract has said nothing
/// Batten can act on, and inventing a refusal from a malformed answer would make
/// Batten the reason a call fails — the inverse of what a fail-open gate is for.
/// Each is reported as a pointer so the author can fix it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Violation {
    /// The program could not be spawned at all.
    ///
    /// Distinct from a handler that ran and failed, because it sends the reader
    /// somewhere else: a missing program is a declaration problem, an exit code
    /// is a behaviour problem.
    NotSpawnable,
    /// The handler outlived its bound and was killed.
    TimedOut(Duration),
    /// The handler exited on a code the contract does not define.
    UndefinedExit(i32),
    /// The handler was killed by a signal.
    Signalled,
    /// The handler wrote a host decision document to stdout.
    ImpersonatedHost,
}

impl Violation {
    /// The pointer line this violation reports as.
    ///
    /// Rule 4, and here it is load-bearing rather than ceremonial: a handler's
    /// streams are user-supplied bytes, so quoting them would put the widest
    /// secret surface on this path into a report. The line carries the handler
    /// id, what it did, and nothing the handler wrote.
    #[must_use]
    pub fn line(&self, id: &str) -> String {
        match self {
            Violation::NotSpawnable => format!("hook.handler {id}: could not spawn"),
            Violation::TimedOut(bound) => format!(
                "hook.handler {id}: exceeded {}ms and was killed",
                bound.as_millis()
            ),
            Violation::UndefinedExit(code) => {
                format!("hook.handler {id}: exit {code} is outside the contract (0, 1, 2)")
            }
            Violation::Signalled => format!("hook.handler {id}: killed by signal"),
            Violation::ImpersonatedHost => format!(
                "hook.handler {id}: wrote a host decision document; a handler reports to batten, \
                 which renders per harness"
            ),
        }
    }
}

/// What one handler said, read under the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
    /// Exit `0`, nothing on stdout. Silence is the pass.
    Pass,
    /// Exit `0` with stdout: advisory text, to be merged into Batten's own
    /// advisory document rather than emitted.
    Advise(String),
    /// Exit [`VIOLATION_EXIT`]: the handler found something and said so.
    Reported(String),
    /// Exit [`DENY_EXIT`]: a refusal, with its reason.
    Deny(String),
    /// The contract was broken. Allows; reported.
    Broke(Violation),
}

/// One handler's answer, its identity and what it cost.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Ran {
    /// The handler's declared id.
    pub id: String,
    /// What it said.
    pub outcome: Outcome,
    /// How long it took, wall clock.
    ///
    /// Recorded for every run including a failing one, because a handler that is
    /// slow *and* broken is the one an author most needs the number for.
    pub took: Duration,
}

/// Every handler's answer for one event, merged.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct Dispatched {
    /// Each handler that ran, in declaration order.
    pub ran: Vec<Ran>,
}

impl Dispatched {
    /// The first refusal, if any handler refused.
    ///
    /// **First, not merged.** A refusal is a stop, and concatenating two of them
    /// would produce a reason no single handler wrote — a composed message
    /// nobody can act on in one hop (§5). Declaration order is the tie-break,
    /// which is why the config surface says order is the running order: a reader
    /// predicts it from the file rather than from a rule.
    #[must_use]
    pub fn refusal(&self) -> Option<(&str, &str)> {
        self.ran.iter().find_map(|ran| match &ran.outcome {
            Outcome::Deny(reason) => Some((ran.id.as_str(), reason.as_str())),
            _ => None,
        })
    }

    /// Every advisory line, in declaration order.
    #[must_use]
    pub fn advice(&self) -> Vec<String> {
        self.ran
            .iter()
            .filter_map(|ran| match &ran.outcome {
                Outcome::Advise(text) | Outcome::Reported(text) => Some(text.clone()),
                _ => None,
            })
            .collect()
    }

    /// Every contract violation, as pointer lines.
    #[must_use]
    pub fn violations(&self) -> Vec<String> {
        self.ran
            .iter()
            .filter_map(|ran| match &ran.outcome {
                Outcome::Broke(violation) => Some(violation.line(&ran.id)),
                _ => None,
            })
            .collect()
    }
}

/// Whether stdout is a host decision document rather than advisory text.
///
/// A cheap structural test, not a parse: a handler that means to advise writes
/// prose or pointer lines, and one that means to decide writes an object with a
/// key a host reads. Both surveyed spellings are named rather than one, so the
/// check does not pass a Claude document while catching a Gemini one.
fn impersonates_host(stdout: &str) -> bool {
    let trimmed = stdout.trim_start();
    if !trimmed.starts_with('{') {
        return false;
    }
    ["hookSpecificOutput", "permissionDecision", "systemMessage"]
        .iter()
        .any(|key| trimmed.contains(key))
}

/// Run every handler declared for `event`, in declaration order.
///
/// Each runs under its own bound, its streams are read rather than forwarded,
/// and its answer is interpreted under the contract in the module docs. Nothing
/// here can fail the call: a handler that cannot run, hangs, or answers outside
/// the contract yields [`Outcome::Broke`], which allows.
#[must_use]
pub fn dispatch(handlers: &[Handler], event: Event, payload: &str) -> Dispatched {
    let mut ran = Vec::new();
    for handler in handlers {
        if handler.event() != Some(event) {
            continue;
        }
        let started = Instant::now();
        let outcome = run_one(handler, payload);
        ran.push(Ran {
            id: handler.id.clone(),
            outcome,
            took: started.elapsed(),
        });
    }
    Dispatched { ran }
}

/// Run one handler and read its answer.
fn run_one(handler: &Handler, payload: &str) -> Outcome {
    let Some((program, args)) = handler.run.split_first() else {
        return Outcome::Broke(Violation::NotSpawnable);
    };
    // THE SAME RESOLUTION EVERY SPAWNING KIND GETS (CLOUD-617). A handler is a
    // program a config names, so it meets Windows' two refusals as a `command`
    // row does. `.` is where a relative name resolves, no `current_dir` being
    // set — the host has already put the process in the right directory.
    #[expect(
        clippy::disallowed_types,
        reason = "stays: this IS the dispatch — a handler is a declared program and running it is the module's whole purpose (CLOUD-898)"
    )]
    let spawned = crate::rules::spawn_resolving(Some(Path::new(".")), program, |program, extra| {
        Command::new(program)
            .args(extra)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
    });
    let Ok(mut child) = spawned else {
        return Outcome::Broke(Violation::NotSpawnable);
    };
    // The payload goes in and the pipe is CLOSED, which is load-bearing rather
    // than tidy: a handler reading stdin to EOF hangs forever against a pipe
    // nobody closes, and that is the exact defect `stop-guard` met and papered
    // over with `timeout 1s cat`. Here the parent closes it, so the ordinary
    // case never reaches the bound at all. The drop is the close.
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write as _;
        let _ = stdin.write_all(payload.as_bytes());
    }
    let bound = handler.timeout();
    let deadline = Instant::now() + bound;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(_) => return Outcome::Broke(Violation::NotSpawnable),
        }
        if Instant::now() >= deadline {
            // Killed, then reaped: leaving a zombie would leak a process per
            // timed-out handler for the life of the hook process.
            let _ = child.kill();
            let _ = child.wait();
            return Outcome::Broke(Violation::TimedOut(bound));
        }
        std::thread::sleep(POLL);
    };
    let stdout = read_stream(child.stdout.take());
    let stderr = read_stream(child.stderr.take());
    interpret(status.code(), &stdout, &stderr)
}

/// Read a child stream to a string, lossily.
///
/// Lossy rather than refusing on invalid UTF-8: a handler emitting a stray byte
/// has a formatting problem, and turning that into "could not look" would
/// discard an otherwise usable verdict over an encoding detail.
fn read_stream(stream: Option<impl Read>) -> String {
    let mut buffer = Vec::new();
    if let Some(mut stream) = stream {
        let _ = stream.read_to_end(&mut buffer);
    }
    String::from_utf8_lossy(&buffer).trim().to_owned()
}

/// Read one handler's exit code and streams under the contract.
///
/// Split from the spawn for [`crate::stop`]'s reason: the interpretation is the
/// part worth testing, and a function that reads a process cannot be tested
/// without one. `None` is a signal death, which [`std::process::ExitStatus`]
/// reports by having no code at all.
fn interpret(code: Option<i32>, stdout: &str, stderr: &str) -> Outcome {
    let Some(code) = code else {
        return Outcome::Broke(Violation::Signalled);
    };
    // Checked before the code is dispatched on, because impersonation is a
    // defect whatever the handler exited with — and a handler writing a host
    // document alongside a clean exit is the case most likely to go unnoticed.
    if impersonates_host(stdout) {
        return Outcome::Broke(Violation::ImpersonatedHost);
    }
    match code {
        0 if stdout.is_empty() => Outcome::Pass,
        0 => Outcome::Advise(stdout.to_owned()),
        VIOLATION_EXIT => Outcome::Reported(reason(stderr, stdout)),
        DENY_EXIT => Outcome::Deny(reason(stderr, stdout)),
        other => Outcome::Broke(Violation::UndefinedExit(other)),
    }
}

/// The reason a non-zero handler gave, preferring stderr.
///
/// stderr is where the contract puts a reason and where every script this
/// replaces already writes one. stdout is the fallback rather than an error,
/// because a handler that put its reason on the wrong stream has still said
/// something true, and discarding it would leave a refusal with no reason at all
/// — which §5 forbids more strongly than it requires a particular stream.
fn reason(stderr: &str, stdout: &str) -> String {
    if stderr.is_empty() {
        stdout.to_owned()
    } else {
        stderr.to_owned()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn handler(id: &str, on: &str, run: &[&str]) -> Handler {
        Handler {
            id: id.to_owned(),
            on: on.to_owned(),
            run: run.iter().map(|word| (*word).to_owned()).collect(),
            timeout_ms: None,
        }
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    #[test]
    fn pre_tool_is_declarable_here_and_is_not_in_action() {
        // The asymmetry IS the design, so it is asserted rather than left to a
        // reader comparing two lists. `action` refuses the adjudicated event
        // because a side effect there runs before a possible deny; a handler is
        // part of that decision, so there is no ordering to invert.
        assert!(declarable_tokens().contains(&Event::PreTool.as_str()));
        assert!(!crate::action::declarable_tokens().contains(&Event::PreTool.as_str()));
    }

    #[test]
    fn unrecognized_is_declarable_by_neither() {
        assert!(!declarable_tokens().contains(&Event::Unrecognized.as_str()));
        let row = handler("h", Event::Unrecognized.as_str(), &["true"]);
        let err = row.validate().unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn a_zero_bound_is_refused_at_load() {
        // A handler that can never succeed is a declaration error, not a runtime
        // one: every call would lose it to a timeout and the author would read
        // the symptom rather than the cause.
        let mut row = handler("h", Event::Stop.as_str(), &["true"]);
        row.timeout_ms = Some(0);
        let err = row.validate().unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn a_duplicate_id_is_refused_because_reports_are_keyed_on_it() {
        let rows = vec![
            handler("same", Event::Stop.as_str(), &["true"]),
            handler("same", Event::PostTool.as_str(), &["true"]),
        ];
        let err = validate(&rows).unwrap_err();
        assert!(is_usage_error(&err));
    }

    #[test]
    fn selects_is_the_narrowing_that_makes_pre_tool_affordable() {
        // CLOUD-460's property at the level this module can assert it: a
        // repository declaring nothing for the event answers without touching a
        // process. The end-to-end cost assertion is the CLI suite's.
        let rows = vec![handler("h", Event::Stop.as_str(), &["true"])];
        assert!(selects(&rows, Event::Stop));
        assert!(!selects(&rows, Event::PreTool));
        assert!(!selects(&[], Event::Stop));
    }

    #[test]
    fn the_default_bound_is_generous_against_what_it_replaces() {
        // Stated as a relation rather than a literal, so re-tuning the constant
        // cannot quietly drop it under the surface it was chosen against.
        assert!(DEFAULT_TIMEOUT >= Duration::from_secs(1));
    }

    #[test]
    fn a_host_document_on_stdout_is_a_violation_not_an_advisory() {
        // The portability property, and the one a well-meaning author is most
        // likely to break: nothing forwards these bytes, so without this the
        // handler would believe it had decided something.
        assert_eq!(
            interpret(Some(0), r#"{"hookSpecificOutput":{"x":1}}"#, ""),
            Outcome::Broke(Violation::ImpersonatedHost)
        );
        assert_eq!(
            interpret(Some(0), r#"  {"permissionDecision":"deny"}"#, ""),
            Outcome::Broke(Violation::ImpersonatedHost)
        );
        assert_eq!(
            interpret(Some(0), r#"{"systemMessage":"hi"}"#, ""),
            Outcome::Broke(Violation::ImpersonatedHost)
        );
        // Prose and pointer lines are what an advisory looks like, and a JSON
        // object that is not a host document is still advisory text: the test is
        // for the host's own keys, not for the shape.
        assert!(matches!(
            interpret(Some(0), "stop.unfinished 2 paths", ""),
            Outcome::Advise(_)
        ));
        assert!(matches!(
            interpret(Some(0), r#"{"count":2}"#, ""),
            Outcome::Advise(_)
        ));
    }

    #[test]
    fn the_contract_reads_every_defined_code_and_refuses_the_rest() {
        assert_eq!(interpret(Some(0), "", ""), Outcome::Pass);
        assert_eq!(
            interpret(Some(0), "a pointer", ""),
            Outcome::Advise("a pointer".to_owned())
        );
        assert_eq!(
            interpret(Some(VIOLATION_EXIT), "", "found it"),
            Outcome::Reported("found it".to_owned())
        );
        assert_eq!(
            interpret(Some(DENY_EXIT), "", "no"),
            Outcome::Deny("no".to_owned())
        );
        assert_eq!(
            interpret(Some(7), "", ""),
            Outcome::Broke(Violation::UndefinedExit(7))
        );
        assert_eq!(
            interpret(None, "", ""),
            Outcome::Broke(Violation::Signalled)
        );
    }

    #[test]
    fn a_reason_on_the_wrong_stream_is_still_a_reason() {
        // §5 requires a refusal to say what to do more strongly than it requires
        // a particular stream, so a handler that wrote its reason to stdout gets
        // read rather than reduced to a refusal with nothing in it.
        assert_eq!(
            interpret(Some(DENY_EXIT), "the reason", ""),
            Outcome::Deny("the reason".to_owned())
        );
    }

    #[test]
    fn the_first_refusal_wins_rather_than_the_reasons_merging() {
        let dispatched = Dispatched {
            ran: vec![
                Ran {
                    id: "first".to_owned(),
                    outcome: Outcome::Deny("no".to_owned()),
                    took: Duration::ZERO,
                },
                Ran {
                    id: "second".to_owned(),
                    outcome: Outcome::Deny("also no".to_owned()),
                    took: Duration::ZERO,
                },
            ],
        };
        assert_eq!(dispatched.refusal(), Some(("first", "no")));
    }

    #[test]
    fn every_violation_allows_and_its_pointer_carries_no_handler_output() {
        // Rule 4 at the widest surface in the module: a handler's streams are
        // user-supplied bytes. Asserted over every variant so a new one cannot
        // land quoting its child.
        let secret = "sk-live-do-not-print";
        for violation in [
            Violation::NotSpawnable,
            Violation::TimedOut(Duration::from_millis(50)),
            Violation::UndefinedExit(7),
            Violation::Signalled,
            Violation::ImpersonatedHost,
        ] {
            let line = violation.line("h");
            assert!(line.starts_with("hook.handler h:"), "{line}");
            assert!(!line.contains(secret), "{line}");
        }
        let dispatched = Dispatched {
            ran: vec![Ran {
                id: "h".to_owned(),
                outcome: Outcome::Broke(Violation::TimedOut(Duration::from_millis(50))),
                took: Duration::from_millis(50),
            }],
        };
        assert_eq!(dispatched.refusal(), None, "a violation never refuses");
        assert_eq!(dispatched.violations().len(), 1);
        assert!(dispatched.advice().is_empty());
    }
}
