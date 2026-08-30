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
//! host decision document, because nothing forwards one.
//!
//! **The ANSWER is normalized; the QUESTION is not, yet.** A handler receives the
//! host's own payload on stdin — the same bytes this process was handed — so a
//! handler that parses `hook_event_name` still reads one host's spelling. That is
//! stated rather than glossed, because the natural reading of the paragraph above
//! is that both directions are portable and only one is. Normalizing the input
//! means projecting [`crate::hook::Envelope`] into the payload instead, which is
//! a separate decision with a rule-4 question attached (`Envelope::input` is
//! documented as never emitted), and it would break every script migrated
//! through this door in the same change that opened it. The output contract is
//! what the door enforces today.
//!
//! A handler that tries anyway is reported as [`Violation::ImpersonatedHost`]
//! rather than passed along — named rather than dropped, because a silently
//! discarded document is an author who believes they are deciding something.

use regex::Regex;
use std::collections::BTreeSet;
use std::io::Read;
use std::path::Path;
#[expect(
    clippy::disallowed_types,
    reason = "stays: a handler IS a program the operator declared in `[[hook.handler]]`, so there is no in-process form of it to prefer — the same standing `action` has (CLOUD-320)"
)]
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
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

/// How long the parent waits for a drained pipe to reach EOF after the child is
/// done, before taking what arrived and abandoning the reader.
///
/// This is not a second timeout on the handler — by the time it is consulted the
/// handler has already exited or been killed on its own bound. It covers only the
/// gap between that and EOF, which is normally instant and is unbounded in exactly
/// one case: an orphaned grandchild still holding the write end. Short, because a
/// verdict that has not arrived by now is not coming, and the bound is the promise.
const DRAIN_GRACE: Duration = Duration::from_millis(200);

/// Server names no connector is exposed under, used to ask a `matcher` whether it
/// accepts a label it has never seen (CLOUD-178).
///
/// Two rather than one, so a fragment cannot pass by coinciding with a single
/// probe's shape, and they are the two forms a host actually mints: a readable
/// alias and a UUID. **Fixed rather than random** — a gate's verdict is
/// byte-stable (house-style §6), and a probe drawn per run would make a refusal
/// depend on the draw. Neither contains `__`, which is the segment separator the
/// fragment is cut on.
const PROBE_SERVERS: [&str; 2] = ["zqxjkvwpbf", "00000000-0000-4000-8000-000000000000"];

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
    /// Which tool names this handler runs for, as a regular expression over the
    /// raw name (CLOUD-312 row 5).
    ///
    /// **Absent means every call at the event**, which is what [`selects`] did for
    /// every row before this column existed — so no landed row changes behaviour by
    /// its arrival.
    ///
    /// # Why a handler needs one at all
    ///
    /// [`selects`] narrows by EVENT, which is the whole narrowing `pre-tool` was
    /// admitted on. That is enough for `user-prompt-submit`, which fires once a
    /// turn. It is not enough for `pre-tool`, which fires on every tool call:
    /// measured 2026-08-25 while retiring `connector-allow-guard`, an unnarrowed
    /// `pre-tool` handler cost **19.6ms p50 on a `Bash` call and 19.9ms on a
    /// `Read`** — calls it has nothing to say about — against a `wired` path whose
    /// whole p50 is 21ms. The guard it replaced was registered under a host matcher
    /// and never saw those calls, so the door would have been a regression dressed
    /// as a consolidation.
    ///
    /// # A regex here, where a rule row gets `tool`
    ///
    /// [`crate::rules::Rule::tool`] is a SUFFIX selector, deliberately: a rule
    /// naming a literal server is the CLOUD-178 trap, where a host rotates the
    /// exposed name and the row silently matches nothing. This column is a regex
    /// instead, because the predicate a dispatched program needs is not always a
    /// suffix — `connector-allow-guard` decides `mcp__<any server>__<any verb>`,
    /// which is a PREFIX and which no suffix selector can say.
    ///
    /// **The trap is refused rather than trusted.** A matcher naming a literal
    /// server segment is exactly what CLOUD-178 measured going inert, so
    /// [`Handler::validate`] rejects one — `^mcp__` is admitted and
    /// `^mcp__Linear__` is not. That keeps the freedom this column needs without
    /// re-opening the defect the sibling column's shape exists to prevent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matcher: Option<String>,
    /// The issue that owns retiring this handler (CLOUD-984).
    ///
    /// **A handler is an antipattern with a ratchet, never a destination.** The
    /// door makes a dispatched program safe — a bound, central fail-open, a
    /// stated output shape — and none of that makes it *policy*. A predicate
    /// living behind a spawn is one the committed authority cannot be read to
    /// discover, so every handler is a debt somebody owes, and this column is
    /// where the creditor is named.
    ///
    /// Absent is not refused at load, deliberately — see
    /// [`Handler::transitional_defect`] for why the enforcement is tree-scoped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// The date past which this handler is overdue, `YYYY-MM-DD`.
    ///
    /// Not an expiry that switches the handler OFF: a dispatched program that
    /// silently stopped running is the fail-open this whole surface exists to
    /// close. It is a date past which the DIAGNOSIS says so, which is the only
    /// form of pressure that cannot itself become an outage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<String>,
    /// Whether this handler's advisory is a **pre-approval** rather than a note.
    ///
    /// CLOUD-191's channel, and the reason it is a column rather than a new exit
    /// code: §7's table is `0/1/2/3` with no per-kind exception, and
    /// [`Outcome::Advise`] already occupies exit `0` with output. A third meaning
    /// distinguished by the *shape* of stdout is exactly what [`impersonates_host`]
    /// refuses, so the capability is DECLARED here and the channel stays the exit
    /// code the handler already has. A row without this behaves exactly as it does
    /// today, and no new vocabulary enters the stream.
    ///
    /// **What it buys.** `connector-allow-guard` reads the session's injected MCP
    /// config to learn which of a server's two names — readable or UUID — is live
    /// this session, and applies the committed verdict to the live spelling. Its
    /// allow arm has to reach the host as `permissionDecision: "allow"` or the
    /// operator is prompted for a grant they already wrote down.
    ///
    /// **What it cannot buy.** A pre-approval only ever upgrades a decision that
    /// was already an allow; the boundary enforces that rather than trusting it, so
    /// no handler can spend a refusal the engine's own rows reached. And it is
    /// refused at load on any event whose host does not honour one, because a
    /// declared grant that lands nowhere is indistinguishable from this handler
    /// never having run.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub preapproves: bool,
}

impl Handler {
    /// The event this handler names, or `None` when `on` names none.
    #[must_use]
    pub fn event(&self) -> Option<Event> {
        event_of(&self.on)
    }

    /// Whether this handler runs for `raw_tool`.
    ///
    /// `true` for a row carrying no matcher, so the column's absence is the
    /// behaviour every row had before it existed. An unparseable matcher also
    /// answers `true`: it is refused at load, so reaching here means a caller
    /// skipped validation, and the safe reading for a participant in a fail-open
    /// contract is to RUN it — a handler that silently stopped being dispatched is
    /// the absence the door exists to close.
    #[must_use]
    pub fn selects_tool(&self, raw_tool: &str) -> bool {
        let Some(matcher) = self.matcher.as_deref() else {
            return true;
        };
        match Regex::new(matcher) {
            Ok(regex) => regex.is_match(raw_tool),
            Err(_) => true,
        }
    }

    /// The bound this handler runs under.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout_ms
            .map_or(DEFAULT_TIMEOUT, Duration::from_millis)
    }

    /// Why this handler's transitional declaration is not in good standing, if
    /// it is not: a stable reason id, or `None` when it is (CLOUD-984).
    ///
    /// **NOT called from [`validate`], and that is the load-bearing decision.**
    /// `config::validate` runs on **every** load, including the mediated path —
    /// so a row refused there fails config load, which is exit 1, which every
    /// harness reads as could-not-look and allows. A missing `owner` would then
    /// disable the entire engine for every call in the repository until somebody
    /// noticed. The failure mode of a strictness is not always strictness.
    ///
    /// So the shape is checked where a red costs a diagnosis rather than the
    /// mediation: `doctor` reads this, and a tree-scoped row can too. `today` is
    /// passed in rather than read, because a predicate that consults the clock
    /// cannot be tested at the boundary it actually fires on.
    #[must_use]
    pub fn transitional_defect(&self, today: crate::waiver::Date) -> Option<&'static str> {
        match self.owner.as_deref() {
            None => return Some("handler-unowned"),
            // A key that is not a key names nobody, which is the state the
            // column exists to prevent — the same reading `wiring-declaration-unowned`
            // takes of a declared row whose owner is a word.
            Some(owner) if !is_issue_key(owner) => return Some("handler-owner-unkeyed"),
            Some(_) => {}
        }
        match self.expires.as_deref() {
            None => Some("handler-undated"),
            // `waiver::Date` rather than a string comparison, and rather than a
            // second date type: it is already the repository's one answer to
            // "what is a date in committed config", it validates the calendar
            // (`2026-02-31` is refused, where a lexicographic compare would sort
            // it happily), and its `Ord` is chronological. A second notion of a
            // date here would be a second authority for one fact.
            Some(text) => match crate::waiver::Date::parse(text) {
                Err(_) => Some("handler-date-malformed"),
                Ok(expiry) if expiry < today => Some("handler-overdue"),
                Ok(_) => None,
            },
        }
    }
}

/// Whether `text` is `<LETTERS>-<DIGITS>` — a tracker key's shape, not a
/// tracker's vocabulary.
///
/// The prefix is not named here: a specific tracker's project key in
/// `crates/batten` is non-negotiable rule 1's violation, and the property worth
/// asserting is that somebody wrote a KEY rather than a word like `soon`.
fn is_issue_key(text: &str) -> bool {
    let Some((prefix, number)) = text.split_once('-') else {
        return false;
    };
    !prefix.is_empty()
        && prefix.chars().all(|c| c.is_ascii_alphabetic())
        && !number.is_empty()
        && number.chars().all(|c| c.is_ascii_digit())
}

impl Handler {
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
        // The matcher compiles, and does not name a server literally.
        //
        // BOTH HALVES ARE REFUSALS AT LOAD rather than per-call surprises, for the
        // reason `key_shape` records one column over: an expression discarded per
        // call leaves the row it qualifies quietly dead, and the direction of that
        // failure is the one that runs the handler on everything.
        if let Some(matcher) = self.matcher.as_deref() {
            Regex::new(matcher).map_err(|err| {
                UsageError::raise(format!(
                    "hook.handler {}: `matcher` is not valid: {err}",
                    self.id
                ))
            })?;
            // CLOUD-178, MECHANIZED RATHER THAN DOCUMENTED. A matcher pinned to one
            // server segment is precisely the shape that measured inert: a claude.ai
            // connector's exposed name is chosen per registration episode by the
            // host, so `^mcp__Linear__` matches nothing the moment it comes back as
            // a UUID — and a handler that stops being dispatched is silent.
            // `^mcp__` is admitted: it names no server, which is what makes it
            // portable. A rule row avoids this by construction (its `tool` column is
            // a suffix); a regex has to be told.
            //
            // THE QUESTION IS ACCEPTANCE, NOT SPELLING, and the difference is a
            // measured bypass rather than a nicety. This clause first asked whether
            // the segment CONTAINED a regex metacharacter, which `^mcp__[L]inear__`
            // satisfies while still accepting only `mcp__Linear__…` — so the check
            // meant to prevent an inert handler admitted one, and `^mcp__(Linear|
            // Gmail)__` passed the same way. Review of #703 caught it. So the
            // segment's own fragment is compiled and asked whether it accepts a
            // server name it has never seen: two probes, fixed rather than random so
            // the verdict is byte-stable, neither one any real connector's label and
            // shaped like the two forms a host actually mints (readable and UUID).
            // A fragment that will not compile alone is could-not-look and admits,
            // which is this module's posture everywhere else.
            if let Some(rest) = matcher.trim_start_matches('^').strip_prefix("mcp__") {
                let fragment = rest.split("__").next().unwrap_or_default();
                if !fragment.is_empty()
                    && let Ok(segment) = Regex::new(&format!("^(?:{fragment})$"))
                    && !PROBE_SERVERS.iter().all(|probe| segment.is_match(probe))
                {
                    return Err(UsageError::raise(format!(
                        "hook.handler {}: `matcher`'s server segment {fragment:?} \
                                 does not accept a server name it has not seen, so it is \
                                 pinned to the label the host exposes today — which is \
                                 rotated per registration episode (CLOUD-178), and this \
                                 handler would then match nothing at all. Match the \
                                 prefix alone (`^mcp__`) and let the program decide the \
                                 rest.",
                        self.id
                    )));
                }
            }
        }
        // A GRANT NEEDS A MOMENT THAT DECIDES PERMISSION, and this is the one half
        // of that question a config load can answer.
        //
        // It cannot ask whether THIS host honours a pre-approval: `validate` runs
        // at config load, which knows nothing about the harness — that answer is
        // `Capabilities::preapprove_reachable`'s, consulted at the boundary, where
        // an unreachable channel degrades to silence. What is decidable here is
        // harness-INDEPENDENT: whether the MOMENT decides permission at all. An
        // inert grant is indistinguishable from the handler not running, which is
        // the failure this whole column exists to remove.
        //
        // `Event::decides_permission` and NOT `carries_a_verdict`, which is the
        // narrower answer and was found by a test rather than by reading: the
        // first version of this borrowed `carries_a_verdict` and admitted
        // `post-tool`, where a deny is a finding about a call that already ran and
        // a grant is permission for something already done. That authority lives
        // on `Event` so this validator and any future reader ask one question.
        if self.preapproves && !event.decides_permission() {
            return Err(UsageError::raise(format!(
                "hook.handler {}: `preapproves` needs a moment that decides permission for a call \
                 that has not run, and {:?} is not one — so the grant would be inert on every \
                 host rather than unreachable on some. Drop the column, or move the row to the \
                 pre-tool event.",
                self.id, self.on
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
pub fn selects(handlers: &[Handler], event: Event, raw_tool: &str) -> bool {
    handlers
        .iter()
        .any(|handler| handler.event() == Some(event) && handler.selects_tool(raw_tool))
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
    /// The handler gave a verdict but wrote no reason on either stream.
    SilentVerdict(i32),
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
            Violation::SilentVerdict(code) => {
                format!("hook.handler {id}: exit {code} with no reason on stdout or stderr")
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
    /// Exit `0` with stdout, from a row declaring [`Handler::preapproves`]: a
    /// **pre-approval** and its reason.
    ///
    /// The same bytes an [`Outcome::Advise`] carries, read differently because the
    /// ROW said so. That is the whole mechanism: §7's exit table has no fourth
    /// code to spend and stdout's shape is already spoken for by
    /// [`impersonates_host`], so the third meaning of exit `0` is declared in
    /// config rather than encoded in the stream.
    ///
    /// **It is a distinct variant rather than a flag on `Advise` so the two cannot
    /// be said twice.** A pre-approval's text is its reason and must not ALSO join
    /// the advisory buffer — at the pre-tool event that buffer reaches nobody
    /// anyway, so a handler whose grant leaked into it would emit a line that
    /// vanishes and a grant that never arrives.
    Preapprove(String),
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

    /// The first pre-approval, if any handler granted one.
    ///
    /// **First, not merged**, on [`Dispatched::refusal`]'s reasoning: a grant is a
    /// single answer, and concatenating two reasons would produce provenance no
    /// handler wrote. Declaration order is the tie-break, which the config surface
    /// already states is the running order.
    ///
    /// A refusal outranks this wherever both exist — checked at the boundary, not
    /// here, because this projection reports what the handlers said and the
    /// precedence between channels is the caller's to enforce.
    #[must_use]
    pub fn preapproval(&self) -> Option<(&str, &str)> {
        self.ran.iter().find_map(|ran| match &ran.outcome {
            Outcome::Preapprove(reason) => Some((ran.id.as_str(), reason.as_str())),
            _ => None,
        })
    }

    /// Every advisory line, in declaration order.
    ///
    /// A pre-approval is deliberately **not** one: its text is a reason travelling
    /// on the permission channel, and emitting it here as well would say the same
    /// thing twice — once where it decides something and once where, at the
    /// pre-tool event, nothing is delivered at all.
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
pub fn dispatch(handlers: &[Handler], event: Event, raw_tool: &str, payload: &str) -> Dispatched {
    let mut ran = Vec::new();
    for handler in handlers {
        if handler.event() != Some(event) {
            continue;
        }
        // THE HALF THAT ACTUALLY SAVES THE SPAWN. `selects` above answers whether
        // ANY handler runs; this decides per row, so a narrowed handler costs a
        // regex rather than a process on every call it does not select.
        if !handler.selects_tool(raw_tool) {
            continue;
        }
        let started = Instant::now();
        let outcome = run_one(handler, payload);
        // THE ROW'S DECLARATION APPLIED EXACTLY ONCE, here, where the row and the
        // outcome are both in hand. Reading `preapproves` anywhere downstream
        // would mean carrying the handler table alongside the results and joining
        // them by id — two authorities for one fact, which is the drift the
        // capability table's own `*_reachable` helpers were extracted to stop.
        //
        // Only an `Advise` converts. An exit `1` or `2` from a pre-approving row
        // still means what §7 says it means: a row may grant when it has nothing
        // to report, and may not turn a finding into a grant.
        let outcome = match outcome {
            Outcome::Advise(text) if handler.preapproves => Outcome::Preapprove(text),
            other => other,
        };
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
    // THE DEADLINE IS ARMED BEFORE ANY PIPE I/O, AND EVERY PIPE GETS ITS OWN
    // THREAD. Both halves are one requirement — the parent must never block on a
    // pipe the CHILD controls — and §7's "a handler that hangs is killed at its
    // bound and the turn still ends" is false without them, which is the whole
    // argument for the door.
    //
    // Doing this serially on one thread was wrong twice, and only the second was
    // bounded:
    //
    //   * writing the payload BEFORE arming the deadline blocks forever once it
    //     exceeds the pipe buffer (64 KiB on Linux, less on macOS) and the
    //     handler does not read stdin. A hook envelope carries the host's raw
    //     JSON, so a large `Write` or `NotebookEdit` body reaches that size. No
    //     bound was running yet, so nothing killed the child: a permanent wedge,
    //     which is exactly what a declared timeout exists to make impossible.
    //   * reading stdout and stderr only AFTER the child exits deadlocks the
    //     pair — the handler blocks writing to a pipe nobody drains, the parent
    //     blocks waiting for an exit that needs that write to finish. The
    //     deadline does fire here, so the cost is a full-timeout stall and a lost
    //     verdict rather than a hang.
    //
    // `exec.rs` already resolved this and says so in its own module docs ("Each
    // pipe is drained on its own thread. Reading them in sequence would…"), so
    // this is that answer reused rather than a new one — and it is the same
    // reason `.claude/rules/rust.md` admits those drains: one thread per pipe for
    // CORRECTNESS, not for speed, which is why no measurement is owed for it.
    //
    // The write still CLOSES the pipe when it finishes, which stays load-bearing:
    // a handler reading stdin to EOF hangs against a pipe nobody closes, the
    // defect `stop-guard` met and papered over with `timeout 1s cat`. Dropping
    // the handle at the end of the closure is that close.
    let bound = handler.timeout();
    let deadline = Instant::now() + bound;
    let stdin_pipe = child.stdin.take();
    let owned = payload.to_owned();
    let (feed_tx, feed_done) = mpsc::channel();
    drop(std::thread::spawn(move || {
        if let Some(mut stdin) = stdin_pipe {
            use std::io::Write as _;
            let _ = stdin.write_all(owned.as_bytes());
        }
        let _ = feed_tx.send(());
    }));
    let (out_buf, out_done) = drain(child.stdout.take());
    let (err_buf, err_done) = drain(child.stderr.take());
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {}
            Err(_) => break None,
        }
        if Instant::now() >= deadline {
            // Killed, then reaped: leaving a zombie would leak a process per
            // timed-out handler for the life of the hook process.
            let _ = child.kill();
            let _ = child.wait();
            timed_out = true;
            break None;
        }
        #[expect(
            clippy::disallowed_methods,
            reason = "the interval of a poll, never the wait itself: the loop exits on `try_wait` \
                      reporting the child reaped, and its outer bound is the `deadline` the caller \
                      declared — `POLL` only says how often to look (CLOUD-1177)"
        )]
        std::thread::sleep(POLL);
    };
    // COLLECTED UNDER A DEADLINE, NEVER BY `join`, and this is the half a first
    // attempt got wrong: `join` requires the thread to FINISH, so it reinstates
    // the unbounded wait one layer down. Killing the child does not necessarily
    // close its pipes — `sh -c "sleep 30"` spawns `sleep` as its own child, which
    // inherits the write ends, so `SIGKILL` to the shell leaves an orphan holding
    // stdout open and the read blocks until that orphan exits. Measured: a 300ms
    // declared bound returned in 30.12s.
    //
    // `exec.rs` states the rule this violates, on its own `seen` buffer: "a return
    // value is only readable by a join that completes, so a deadline over a
    // returned `Vec` could only ever store nothing." So the buffer is SHARED and
    // the wait is bounded, exactly as `PIPE_DRAIN_TIMEOUT` does there — what
    // arrived is read, and a thread still blocked on an orphan's pipe is
    // abandoned rather than waited for.
    //
    // The orphan itself is a cost, stated rather than hidden: it outlives the call
    // and is reaped by init. Killing the process GROUP would collect it, which is
    // what `exec.rs::group_at_spawn` exists for, and is the right follow-up; it is
    // not what keeps the bound honest, and the bound is this module's promise.
    let grace = DRAIN_GRACE;
    let _ = out_done.recv_timeout(grace);
    let _ = err_done.recv_timeout(grace);
    let _ = feed_done.recv_timeout(grace);
    let stdout = taken(&out_buf);
    let stderr = taken(&err_buf);
    if timed_out {
        return Outcome::Broke(Violation::TimedOut(bound));
    }
    let Some(status) = status else {
        return Outcome::Broke(Violation::NotSpawnable);
    };
    interpret(status.code(), &stdout, &stderr)
}

/// Drain one child stream on its own thread, into a buffer the caller can read
/// WITHOUT waiting for the thread to finish.
///
/// The shared buffer is the whole point, and it is `exec.rs`'s reasoning rather
/// than a new one: *"a return value is only readable by a join that completes, so
/// a deadline over a returned `Vec` could only ever store nothing."* A handler's
/// pipe can outlive the handler — an orphaned grandchild keeps the write end open
/// past a `SIGKILL` to its parent — so the caller must be able to take what
/// arrived and walk away.
///
/// The channel says "EOF reached", so the caller can wait for a clean finish when
/// there is one and stop waiting when there is not.
fn drain(stream: Option<impl Read + Send + 'static>) -> (Arc<Mutex<Vec<u8>>>, mpsc::Receiver<()>) {
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let (tx, rx) = mpsc::channel();
    let handle = Arc::clone(&buffer);
    drop(std::thread::spawn(move || {
        if let Some(mut stream) = stream {
            let mut chunk = [0_u8; 8192];
            loop {
                let read = match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => read,
                };
                // Appended per chunk rather than at EOF, for the reason the
                // shared buffer exists at all: a drain abandoned at the deadline
                // must still have delivered everything it had already read.
                if let Ok(mut seen) = handle.lock() {
                    seen.extend_from_slice(chunk.get(..read).unwrap_or(&[]));
                }
            }
        }
        let _ = tx.send(());
    }));
    (buffer, rx)
}

/// Read a drained buffer as a string, lossily.
///
/// Lossy rather than refusing on invalid UTF-8: a handler emitting a stray byte
/// has a formatting problem, and turning that into "could not look" would
/// discard an otherwise usable verdict over an encoding detail.
///
/// A poisoned lock reads as empty for the same reason — the only writer is the
/// drain thread above, so a poisoning means that thread panicked and there is no
/// verdict to recover either way.
fn taken(buffer: &Arc<Mutex<Vec<u8>>>) -> String {
    buffer.lock().map_or_else(
        |_| String::new(),
        |seen| String::from_utf8_lossy(&seen).trim().to_owned(),
    )
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
        VIOLATION_EXIT | DENY_EXIT => {
            let reason = reason(stderr, stdout);
            // A VERDICT THAT NAMES NOTHING IS NOT ONE §5 CAN CARRY, and the
            // handler is the only party that could have named a remedy — Batten
            // cannot invent one for a program whose predicate it does not know.
            // `reason` already falls back from stderr to stdout, so both empty
            // means the handler refused and said nothing at all.
            //
            // Reported as a CONTRACT VIOLATION rather than forwarded, which
            // means it fails open: an empty deny reaching the host would be the
            // un-actionable refusal CLOUD-122 exists to prevent, and a broken
            // handler must not be able to block a call (§7's fail-open, and the
            // exit table's rule that no Batten failure blocks).
            if reason.is_empty() {
                return Outcome::Broke(Violation::SilentVerdict(code));
            }
            if code == DENY_EXIT {
                Outcome::Deny(reason)
            } else {
                Outcome::Reported(reason)
            }
        }
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
            matcher: None,
            // Absent, so the existing cases keep exercising what they were
            // written for: `validate` deliberately does NOT read these, and a
            // helper that populated them would hide that separation rather than
            // pin it. `transitional_defect`'s own cases construct their rows.
            owner: None,
            expires: None,
            // `false`, so every existing case still exercises the ordinary
            // advisory path. The pre-approval cases set it explicitly, which is
            // what keeps the conversion in `dispatch` visible as a decision the
            // ROW makes rather than a default this helper hides.
            preapproves: false,
        }
    }

    fn dated(id: &str, owner: Option<&str>, expires: Option<&str>) -> Handler {
        let mut row = handler(id, "user-prompt-submit", &["mise-tasks/x.sh"]);
        row.owner = owner.map(str::to_owned);
        row.expires = expires.map(str::to_owned);
        row
    }

    const fn on(year: u64, month: u64, day: u64) -> crate::waiver::Date {
        crate::waiver::Date { year, month, day }
    }

    /// A transitional declaration is judged, and every way it can be wrong has
    /// its own reason id (CLOUD-984).
    ///
    /// A handler is an antipattern with a ratchet, so the column that names who
    /// retires it is the difference between a debt and a destination. Each arm
    /// sends the reader somewhere different — nobody named, a word where a key
    /// belongs, no date, a date that is not one, and a date that has passed — so
    /// one shared reason would be a pointer that answers none of them.
    ///
    /// Fails by: collapsing any two arms onto one reason id.
    #[test]
    fn every_way_a_transitional_declaration_can_be_wrong_has_its_own_reason() {
        let today = on(2026, 8, 26);

        assert_eq!(
            dated("a", None, Some("2099-01-01")).transitional_defect(today),
            Some("handler-unowned")
        );
        assert_eq!(
            dated("a", Some("soon"), Some("2099-01-01")).transitional_defect(today),
            Some("handler-owner-unkeyed"),
            "a word is not a key: it reads as a decision and records nobody to ask"
        );
        assert_eq!(
            dated("a", Some("CLOUD-984"), None).transitional_defect(today),
            Some("handler-undated")
        );
        assert_eq!(
            dated("a", Some("CLOUD-984"), Some("next tuesday")).transitional_defect(today),
            Some("handler-date-malformed")
        );
        assert_eq!(
            dated("a", Some("CLOUD-984"), Some("2026-08-25")).transitional_defect(today),
            Some("handler-overdue"),
            "yesterday has passed"
        );

        // In good standing: today itself is not yet overdue, which is the
        // boundary an off-by-one would move.
        assert_eq!(
            dated("a", Some("CLOUD-984"), Some("2026-08-26")).transitional_defect(today),
            None
        );
        assert_eq!(
            dated("a", Some("CLOUD-984"), Some("2099-01-01")).transitional_defect(today),
            None
        );
    }

    /// The date is a calendar date, not a string comparison.
    ///
    /// `waiver::Date` is reused rather than a second notion of a date, and this
    /// is what that buys: an impossible day is refused where a lexicographic
    /// compare would sort it happily and read as live until the year 2027.
    ///
    /// Fails by: swapping `Date::parse` for a shape-only check and `<` on `&str`.
    #[test]
    fn an_impossible_date_is_malformed_rather_than_merely_late() {
        let today = on(2026, 8, 26);
        for impossible in ["2026-02-31", "2026-13-01", "2026-00-10", "2026-8-1"] {
            assert_eq!(
                dated("a", Some("CLOUD-984"), Some(impossible)).transitional_defect(today),
                Some("handler-date-malformed"),
                "{impossible} is not a date"
            );
        }
    }

    /// `validate` does not read the transitional columns, and that is deliberate.
    ///
    /// `config::validate` runs on EVERY load including the mediated path, so a
    /// row refused there fails config load — exit 1, which a harness reads as
    /// could-not-look and allows. A missing `owner` would disable the engine for
    /// every call in the repository until somebody noticed. The enforcement is
    /// `doctor`'s, where a red costs a diagnosis rather than the mediation.
    ///
    /// Fails by: calling `transitional_defect` from `validate`.
    #[test]
    fn a_handler_with_no_transitional_columns_still_loads() {
        let bare = handler("mcp-attach-check", "user-prompt-submit", &["x.sh"]);
        assert!(
            bare.validate().is_ok(),
            "an unowned handler must not fail config load — that is fail-open on every call"
        );
        assert!(
            bare.transitional_defect(on(2026, 8, 26)).is_some(),
            "and it is still a finding where findings are cheap"
        );
    }

    fn is_usage_error(err: &anyhow::Error) -> bool {
        err.downcast_ref::<UsageError>().is_some()
    }

    /// A payload past any platform's pipe buffer: 64 KiB on Linux, less on macOS.
    ///
    /// The size is the whole point of these two cases rather than incidental —
    /// under the buffer the parent's write completes into the kernel and neither
    /// defect below can appear, which is why the serial version passed its own
    /// tests for as long as every fixture payload was small.
    fn oversized() -> String {
        "x".repeat(256 * 1024)
    }

    #[test]
    fn a_handler_that_never_reads_stdin_cannot_wedge_the_parent() {
        // THE CRITICAL CASE (found by CodeRabbit on #632). The payload was
        // written BEFORE the deadline was armed, so a handler that does not read
        // stdin left the parent blocked in `write_all` on a full pipe with no
        // bound running and nothing to kill the child.
        //
        // THE FIXTURE HAS TO STAY ALIVE, and the first version of this case did
        // not: `sh -c "exit 0"` never reads stdin but dies at once, so the read
        // end closes, the write fails with `EPIPE` immediately, and NOTHING
        // blocks. Run against the un-fixed code it passed in 0.00s — a test
        // asserting its own premise before its conclusion, which is the shape
        // `.claude/rules/rust.md` names and `tests/primitives.rs` gates. A child
        // that sleeps holds the read end open, which is what makes the parent's
        // write block and the defect reachable.
        //
        // The BOUND is the assertion, in both senses: the outcome must be the
        // timeout rather than a hang, and it must arrive on the handler's own
        // deadline rather than the child's. Elapsed time is the subject here, so
        // measuring it is the assertion rather than a proxy for one.
        let mut deaf = handler("deaf", "stop", &["sh", "-c", "sleep 30"]);
        deaf.timeout_ms = Some(300);
        let started = Instant::now();
        let outcome = run_one(&deaf, &oversized());
        let took = started.elapsed();
        assert!(
            matches!(outcome, Outcome::Broke(Violation::TimedOut(_))),
            "expected the declared bound to fire, got {outcome:?}"
        );
        assert!(
            took < Duration::from_secs(5),
            "the bound must govern the whole call: took {took:?} against a 300ms timeout, which \
             means the parent blocked writing stdin before the deadline was armed"
        );
    }

    #[test]
    fn a_handler_that_floods_stdout_still_returns_its_verdict() {
        // The second half of the same root cause: stdout and stderr were read
        // only AFTER the child exited, so a handler writing past the pipe buffer
        // blocked on its own write while the parent waited for an exit that could
        // not happen. Bounded, unlike the case above — the deadline fired — but it
        // cost a full-timeout stall and threw away a verdict the handler had
        // already reached.
        //
        // Asserted as `Advise` with the bytes intact, so both halves are pinned:
        // the call returns, and it returns what the handler actually said.
        // `head`/`tr` rather than a shell loop: this has to finish well inside the
        // default bound, or the test would pass for the wrong reason on a slow box.
        let big = 200 * 1024;
        let script = format!("head -c {big} /dev/zero | tr '\\0' a");
        let outcome = run_one(&handler("loud", "stop", &["sh", "-c", &script]), "{}");
        match outcome {
            Outcome::Advise(said) => assert_eq!(
                said.len(),
                big,
                "the whole stream is drained, not the first pipe buffer's worth"
            ),
            other => panic!("expected the handler's advisory, got {other:?}"),
        }
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
        assert!(selects(&rows, Event::Stop, ""));
        assert!(!selects(&rows, Event::PreTool, ""));
        assert!(!selects(&[], Event::Stop, ""));
    }

    #[test]
    fn a_matcher_narrows_the_event_to_the_calls_it_names() {
        // THE SECOND NARROWING, and the measurement that bought it (CLOUD-312 row
        // 5): `pre-tool` fires on every tool call, so an unnarrowed handler cost
        // 19.6ms p50 on a `Bash` call against a `wired` path whose whole p50 is
        // 21ms. The guard it replaced was registered under a host matcher and never
        // saw those calls.
        let mut row = handler("h", Event::PreTool.as_str(), &["true"]);
        row.matcher = Some("^mcp__".to_owned());
        let rows = vec![row];
        assert!(
            selects(&rows, Event::PreTool, "mcp__Linear__save_issue"),
            "the calls the matcher names still select it"
        );
        assert!(
            !selects(&rows, Event::PreTool, "Bash"),
            "and a call it does not name costs a regex rather than a process"
        );
        // Absence is the behaviour every row had before the column existed, so no
        // landed row changes by its arrival.
        let bare = vec![handler("h", Event::PreTool.as_str(), &["true"])];
        assert!(selects(&bare, Event::PreTool, "Bash"));
    }

    #[test]
    fn a_matcher_naming_a_server_literally_is_refused() {
        // CLOUD-178, mechanized rather than documented: a claude.ai connector's
        // exposed name is chosen per registration episode, so a matcher naming one
        // matches nothing the moment it comes back as a UUID — and a handler that
        // stopped being dispatched is silent. The prefix alone is portable.
        let mut named = handler("h", Event::PreTool.as_str(), &["true"]);
        named.matcher = Some("^mcp__Linear__".to_owned());
        let err = named.validate().expect_err("a literal server is refused");
        assert!(is_usage_error(&err), "and it is a usage error: {err}");

        let mut portable = handler("h", Event::PreTool.as_str(), &["true"]);
        portable.matcher = Some("^mcp__".to_owned());
        assert!(
            portable.validate().is_ok(),
            "the prefix alone names no server and is admitted"
        );
        // The anti-vacuity half: a matcher that is not about MCP at all is not the
        // trap and must not be caught by it.
        let mut other = handler("h", Event::PreTool.as_str(), &["true"]);
        other.matcher = Some("^Bash$".to_owned());
        assert!(other.validate().is_ok(), "an ordinary tool matcher passes");

        let mut broken = handler("h", Event::PreTool.as_str(), &["true"]);
        broken.matcher = Some("^mcp__(".to_owned());
        assert!(
            broken.validate().is_err(),
            "an unparseable matcher is refused at load, not discarded per call"
        );
    }

    #[test]
    fn a_server_pinned_matcher_spelled_with_metacharacters_is_still_refused() {
        // THE REGRESSION, and it is a bypass this clause once admitted. Deciding by
        // SPELLING — "does the segment contain a regex metacharacter" — passes
        // `^mcp__[L]inear__`, which `is_match` still accepts only for
        // `mcp__Linear__…`. So the check meant to prevent an inert handler admitted
        // one, in the exact shape CLOUD-178 measured. Review of #703 caught it; the
        // clause asks about ACCEPTANCE now, which is the property that matters.
        for pinned in [
            "^mcp__[L]inear__",
            "^mcp__(Linear|Gmail)__",
            "^mcp__Lin(ear)__",
            "^mcp__Linear?__",
        ] {
            let mut row = handler("h", Event::PreTool.as_str(), &["true"]);
            row.matcher = Some(pinned.to_owned());
            let err = row
                .validate()
                .expect_err("a segment that accepts no unseen server is refused");
            assert!(is_usage_error(&err), "and it is a usage error: {err}");
            // Pointer-only (rule 4): the refusal names the fragment it judged and
            // the issue that explains why, never a byte of any payload.
            assert!(
                format!("{err}").contains("CLOUD-178"),
                "the refusal points at the defect it mechanizes: {err}"
            );
        }
    }

    #[test]
    fn a_server_agnostic_segment_is_admitted_even_when_the_matcher_says_more() {
        // The positive arm, without which the clause above would refuse every MCP
        // matcher and read as coverage. A segment that accepts a name it has never
        // seen survives a rotation, which is the whole property; naming a SUFFIX
        // beyond it is what the retiring guards did and is portable by construction.
        for portable in [
            "^mcp__",
            "^mcp__.*__save_issue",
            "^mcp__[^_]+__save_issue",
            "^mcp__.+__(subscribe_pr_activity|send_later)",
        ] {
            let mut row = handler("h", Event::PreTool.as_str(), &["true"]);
            row.matcher = Some(portable.to_owned());
            assert!(
                row.validate().is_ok(),
                "a server-agnostic segment is admitted: {portable}"
            );
        }
    }

    // ---------------------------------------------------------------------
    // The pre-approval channel (CLOUD-191's half that the door lost).
    // ---------------------------------------------------------------------

    #[test]
    fn an_advisory_becomes_a_grant_only_where_the_row_declares_it() {
        // THE DISCRIMINATING PAIR, and the whole mechanism is the difference
        // between them: identical bytes, identical exit, and the row decides which
        // channel they travel. Asserting one without the other would pass on a
        // build that converted every advisory into a grant.
        let payload = "{}";
        let mut row = handler("g", Event::PreTool.as_str(), &["sh", "-c", "echo granted"]);

        let dispatched = dispatch(
            std::slice::from_ref(&row),
            Event::PreTool,
            "mcp__x__y",
            payload,
        );
        assert_eq!(
            dispatched.advice(),
            vec!["granted".to_owned()],
            "without the column the text is advice, exactly as before"
        );
        assert_eq!(
            dispatched.preapproval(),
            None,
            "and it is not a grant, or the column would express nothing"
        );

        row.preapproves = true;
        let dispatched = dispatch(
            std::slice::from_ref(&row),
            Event::PreTool,
            "mcp__x__y",
            payload,
        );
        assert_eq!(
            dispatched.preapproval(),
            Some(("g", "granted")),
            "with the column the same bytes are the grant's reason"
        );
        assert!(
            dispatched.advice().is_empty(),
            "and they are NOT also advice: said twice, the grant would emit a line \
             that vanishes at pre-tool and a reason that arrives"
        );
    }

    #[test]
    fn a_declaring_row_may_still_report_and_refuse() {
        // The column converts an `Advise` and nothing else. A row that can grant
        // must not have lost the ability to say "I found something" or "no" —
        // otherwise declaring it would silently disarm the guard's other arms,
        // which is the shape this whole surface exists to refuse.
        let mut row = handler(
            "g",
            Event::PreTool.as_str(),
            &["sh", "-c", "echo no >&2; exit 2"],
        );
        row.preapproves = true;
        let dispatched = dispatch(
            std::slice::from_ref(&row),
            Event::PreTool,
            "mcp__x__y",
            "{}",
        );
        assert_eq!(dispatched.refusal(), Some(("g", "no")));
        assert_eq!(
            dispatched.preapproval(),
            None,
            "a refusal is not a grant, whatever the row declares"
        );
    }

    #[test]
    fn a_grant_on_a_moment_that_decides_no_permission_is_refused_at_load() {
        // The one half of "does this land anywhere" a config load can answer.
        // `validate` cannot know the harness, so it cannot ask whether THIS host
        // honours a grant — that is the boundary's question, and an unreachable
        // channel there degrades to silence. What is decidable here is
        // harness-independent: there is no permission to grant at `stop`, on any
        // host, so such a row is inert everywhere rather than unreachable
        // somewhere.
        //
        // `post-tool` AND `user-prompt-submit` are the load-bearing entries, and
        // they are why this asks `decides_permission` rather than
        // `carries_a_verdict`. Both DO carry a verdict, so the first version of
        // this refusal admitted them — and on both a grant is meaningless: the
        // call is over, or there is no call. This case is what found that.
        //
        // Fails by: widening the predicate back to `carries_a_verdict`.
        for inert in [
            "stop",
            "session-start",
            "post-tool",
            "post-tool-batch",
            "user-prompt-submit",
        ] {
            let mut row = handler("g", inert, &["true"]);
            row.preapproves = true;
            let err = row
                .validate()
                .expect_err("a grant needs a moment that decides permission");
            assert!(
                format!("{err}").contains("decides permission"),
                "the refusal says WHY rather than merely refusing: {err}"
            );
        }
    }

    #[test]
    fn a_grant_on_the_adjudicated_moment_loads() {
        // The positive arm, without which the case above passes on a build that
        // refuses every `preapproves` row.
        let mut row = handler("g", Event::PreTool.as_str(), &["true"]);
        row.preapproves = true;
        assert!(row.validate().is_ok());
    }

    #[test]
    fn the_first_grant_wins_and_a_refusal_outranks_every_grant() {
        // Declaration order is the tie-break among grants, on `refusal`'s own
        // reasoning: concatenating two would produce provenance no handler wrote.
        //
        // The second half is the safety one. Two handlers disagreeing about one
        // call must resolve toward the refusal, because a grant that could
        // overrule one would let a dispatched program spend a verdict another
        // dispatched program reached. Asserted here rather than trusted, because
        // this projection is what the boundary reads.
        let mut first = handler("a", Event::PreTool.as_str(), &["sh", "-c", "echo one"]);
        first.preapproves = true;
        let mut second = handler("b", Event::PreTool.as_str(), &["sh", "-c", "echo two"]);
        second.preapproves = true;
        let rows = vec![first, second.clone()];
        let dispatched = dispatch(&rows, Event::PreTool, "mcp__x__y", "{}");
        assert_eq!(dispatched.preapproval(), Some(("a", "one")));

        let denier = handler(
            "d",
            Event::PreTool.as_str(),
            &["sh", "-c", "echo nope >&2; exit 2"],
        );
        let rows = vec![second, denier];
        let dispatched = dispatch(&rows, Event::PreTool, "mcp__x__y", "{}");
        assert_eq!(dispatched.refusal(), Some(("d", "nope")));
        assert_eq!(
            dispatched.preapproval(),
            Some(("b", "two")),
            "the projection still reports what each handler said; the PRECEDENCE \
             between the two channels is the boundary's to enforce, and asserting \
             it here would move it"
        );
    }

    #[test]
    fn a_declaring_row_that_writes_a_host_document_is_still_a_violation() {
        // The column does not buy a way past the impersonation check. A row
        // allowed to grant is exactly the row whose author is most tempted to
        // write `permissionDecision` by hand, so the two must not interact.
        let mut row = handler(
            "g",
            Event::PreTool.as_str(),
            &[
                "sh",
                "-c",
                r#"printf '{"hookSpecificOutput":{"permissionDecision":"allow"}}'"#,
            ],
        );
        row.preapproves = true;
        let dispatched = dispatch(
            std::slice::from_ref(&row),
            Event::PreTool,
            "mcp__x__y",
            "{}",
        );
        assert_eq!(dispatched.preapproval(), None);
        assert_eq!(
            dispatched.violations(),
            vec![Violation::ImpersonatedHost.line("g")]
        );
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
    fn a_verdict_with_no_reason_on_either_stream_breaks_rather_than_refusing() {
        // The gap CodeRabbit found on #632: `reason` returns "" when both streams
        // are empty, and `Outcome::Deny("")` became a `Refusal` with an empty
        // reason and `Fix::None` — a host-facing deny naming nothing, which is
        // the un-actionable refusal §5 forbids and CLOUD-122 exists to prevent.
        //
        // Reported rather than forwarded, so it FAILS OPEN: a handler broken this
        // way cannot block a call. Both verdict codes, because a silent `1` is
        // the same defect on the reporting channel.
        assert_eq!(
            interpret(Some(DENY_EXIT), "", ""),
            Outcome::Broke(Violation::SilentVerdict(DENY_EXIT))
        );
        assert_eq!(
            interpret(Some(VIOLATION_EXIT), "", ""),
            Outcome::Broke(Violation::SilentVerdict(VIOLATION_EXIT))
        );
        // Whitespace never reaches here as a "reason": `read_stream` trims, so a
        // handler that echoed a bare newline arrives as the empty case above.
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
            Violation::SilentVerdict(2),
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
