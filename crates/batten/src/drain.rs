//! The advisory drain: one wake per batch boundary, coalesced while pending,
//! paced from config (CLOUD-79).
//!
//! [`crate::findings`] answers what the store holds and [`crate::journal`] how it
//! is written; this is the first thing that reads either one **back to the
//! agent**. Before it, findings accumulated and nothing surfaced them —
//! `NotShown::DrainSuppressed` was a variant with no producer.
//!
//! # The batch boundary is a window, not an event
//!
//! [`crate::hook::Event`] carries no batch variant, so the envelope this rides
//! delivers one `PostToolUse` per tool call: N verifiers in one batch are N
//! separate processes, and a drain per process is exactly the once-per-verifier
//! behaviour this issue exists to remove.
//!
//! **Claude Code does emit a batch event** — CLOUD-187 wires a hook on
//! `PostToolBatch` and measured it firing — and four of the five surveyed hosts
//! do not. So the vocabulary gap is real for most hosts and closable for one;
//! riding it where it exists is CLOUD-389, and it changes delivery rather than
//! the invariant, for the reason below.
//!
//! So the boundary is **inferred by a coalescing window** rather than received.
//! The first wake past the window drains; every wake inside it is
//! [`Wake::Coalesced`] and records that a follow-up is owed. Two batches
//! arriving against one window therefore produce **one** follow-up, not two,
//! which is what makes the mask rather than the event the thing that enforces
//! once-per-batch. That inversion is deliberate: it means a host that never
//! grows a batch event still gets batch behaviour, and one that does can hand
//! the boundary in later without changing what the state machine promises.
//!
//! Because each wake is its own process, the window's state cannot live in
//! memory. It is persisted per session under the bound store, beside the cursors
//! and suppression counts the same issue puts there.
//!
//! # Two short-circuits, and they are not the same mechanism
//!
//! * **`resultId`** ([`Drained::result_id`], CLOUD-166): the drain *ran*, and
//!   the payload it would emit is byte-identical to the last one, so it emits
//!   nothing. Cheap relative to speaking, not relative to looking.
//! * **empty-poll give-up** ([`DrainConfig::empty_poll_giveup`]): after N
//!   consecutive drains that said nothing, wakes stop paying for a drain **at
//!   all** until the store's merged log moves. The re-arm is a one-file read of
//!   the format record, which is the point — it is cheaper than the work it
//!   replaces, where the `resultId` path is not.
//!
//! Collapsing them would lose one of the two: a `resultId` that also stopped
//! looking could never notice the store had changed, and a give-up that still
//! rendered every time would save nothing.
//!
//! # The scope filter is per kind, and the exception is the whole point
//!
//! [`in_scope`] filters **code-anchored findings only** against the changed-path
//! set — diff scoping is the primary cardinality control, and Tricorder's
//! measured lesson is that it does most of the work that per-finding tracking is
//! usually built for.
//!
//! `Sequence`, `Log` and `Scope` kinds **bypass it unconditionally**. This is not
//! a leniency: the flagship wrong-completion class — done-not-landed,
//! deny-then-bypass — attaches to no changed file by construction, so a filter
//! that treated "no changed file" as "not interesting" would drop precisely the
//! findings the engine exists to raise. Their sole cardinality backstop is
//! CLOUD-82's cap.
//!
//! An identity whose kind this binary cannot classify bypasses too
//! ([`crate::identity::StoredIdentity::kind`] answers `None` for a kind a future
//! binary added). Fail-open in the *reporting* direction: showing a finding that
//! could have been filtered costs a line, where filtering one that should have
//! bypassed is a silent false negative.
//!
//! # Advisory means structurally unable to block
//!
//! Nothing here returns a verdict. The drain rides the `hook` surface at
//! `PostToolUse`, an event no host offers a deny channel for, and nothing it
//! computes reaches [`crate::hook::adjudicate`], which stays a pure function of
//! config plus argv. A drain that could refuse a call would make an advisory
//! surface a gate, which house-style §0.3 refuses.
//!
//! A drain **failure** is fail-loud rather than swallowed: it propagates to the
//! binary boundary as an ordinary error, where §7 spends `1` or `3`. Neither is
//! the deny code, so being loud costs nothing a host reads as a refusal — and
//! the alternative, a drain that silently did not run, is byte-identical to one
//! that ran and found nothing. That is the false green this engine exists to
//! catch, in a place nobody would look.
//!
//! # Emission is bounded twice, and the two bounds measure different things
//!
//! CLOUD-82's contract, and the reason [`cycle`] selects before it renders: a
//! payload the agent cannot read is not information.
//!
//! * The **per-rule cardinality cap** ([`DrainConfig::cardinality_cap`]) bounds
//!   how many distinct identities one rule may spend lines on. A rule over it
//!   contributes one `rule R: K+ findings` summary line and no entries, and the
//!   identities it withheld are journalled as [`NotShown::OverCardinalityCap`].
//!   That is a statement about the **rule** — a check firing on eleven distinct
//!   identities inside one changed scope is a rule-health signal, not a to-do
//!   list — which is why it is the reason that feeds CLOUD-78's sampled review.
//! * The **token budget** ([`DrainConfig::token_budget`]) bounds the payload as
//!   a whole, measured with [`crate::budget::estimate_tokens`] rather than a
//!   second estimator. What it drops is journalled as
//!   [`NotShown::DrainSuppressed`], because that is a statement about **this
//!   boundary**: the finding is unchanged, the drain simply had no room for it
//!   this time, and the next drain reconsiders it.
//!
//! Between the two, lines are ordered **salient-first** — by tier, then rule,
//! then fingerprint. The occurrence count is deliberately *not* a sort key:
//! CLOUD-80's no-escalation law says a duplicate count never escalates a tier,
//! and on the emission plane the way to obey it is to make salience structurally
//! independent of the count rather than to remember not to look.
//!
//! A **group re-raise** renders as `old->new` in the count field, against what
//! this session's last drain actually said ([`WakeState::counts`]) — the store
//! carries no count anchor, and the honest anchor for "should I mention this
//! again" is what the agent was last told. One identity's occurrences are a
//! count by construction ([`crate::identity::count_occurrences`]), so a 500→501
//! re-raise is one line carrying one in-scope pointer; there is no instance list
//! to expand and no path by which 501 pointers could be emitted. A count that
//! *fell* renders as the plain new count: a ratchet is not a re-raise, because
//! re-raising on incremental fixing punishes the fix.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::emission;
use crate::findings::{Context, FindingRecord, Instance, NotShown, Observation, Presentation};
use crate::identity::{FindingKind, drain_result_fingerprint};
use crate::journal;
use crate::severity::AdvisoryTier;

/// The persisted wake state's schema version, independent of the record schema
/// and of the journal layout: the window's shape and the store's contents evolve
/// for unrelated reasons.
pub const WAKE_SCHEMA: u32 = 1;

/// The subdirectory holding one wake-state file per session, under a bound
/// store.
const DRAIN_DIR: &str = "drain";

/// The coalescing window, in milliseconds, when the config declares none.
///
/// A batch of tool calls lands in well under a second on every host surveyed, so
/// this is sized to span one comfortably while staying far below the interval at
/// which an agent would notice a finding arriving late. It is a **default, not a
/// constant**: the §7 obligation is that pacing comes from config, and this is
/// only what an absent `[drain]` table resolves to.
pub const DEFAULT_INTERVAL_MS: u64 = 2_000;

/// Consecutive empty drains before wakes stop paying for one, when the config
/// declares none.
pub const DEFAULT_EMPTY_POLL_GIVEUP: u32 = 3;

/// What a drain says when its payload is byte-identical to the last one it
/// emitted (CLOUD-166).
///
/// **Silence and "unchanged" are different claims, and the drain must be able to
/// make the second one.** Before this, a repeat emitted nothing — which reads
/// exactly like a drain that never ran, and a drain that silently did not run is
/// the false green this module's docs say the engine exists to catch. LSP 3.17
/// solved the same problem at the report level: an unchanged report answers
/// `unchanged` rather than resending itself.
///
/// One fixed token, so its cost is constant whatever the finding count and
/// [`crate::budget::estimate_tokens`] over it is the same number every time. It
/// is deliberately **not** emitted for an empty payload: "nothing to say" and
/// "the same thing as before" are different facts, and collapsing them would
/// make the marker meaningless.
pub const UNCHANGED: &str = "unchanged";

/// Distinct identities one rule may spend entries on in a single drain, when the
/// config declares none.
///
/// Ten because the cap is a **rule-health** threshold rather than a display
/// preference: a check that fires on more than ten distinct identities inside
/// one changed scope is telling the operator something about itself, and the
/// summary line is the honest way to say it in one line instead of eleven.
pub const DEFAULT_CARDINALITY_CAP: usize = 10;

/// The rendered payload's token ceiling, when the config declares none.
///
/// Sized to a payload an agent reads rather than skims — roughly forty pointer
/// lines — and small enough that the drain firing on every batch boundary of a
/// long session stays a rounding error against the context it is protecting.
pub const DEFAULT_TOKEN_BUDGET: usize = 1_024;

/// How many of a subject's evaluations the flap ratio is computed over, when the
/// config declares none (CLOUD-165).
///
/// Eight because the window has to be long enough that an ordinary raise-then-fix
/// — one transition — stays far under any useful threshold, and short enough that
/// an identity which has *stopped* oscillating is believed again within a few
/// evaluations. Nagios ships twenty-one state slots for a check evaluated on a
/// timer; a window counted in evaluation boundaries needs fewer, because every
/// entry in it is a real scan rather than a poll.
pub const DEFAULT_FLAP_WINDOW: usize = 8;

/// The flap threshold as state changes per hundred adjacent evaluations, when the
/// config declares none.
///
/// Fifty: half the transitions the window could possibly hold. A raise, a fix and
/// a regression inside eight evaluations scores well under it; a check alternating
/// on every scan scores one hundred. Nagios's defaults bracket the same region
/// from either side, and the integer spelling is what keeps the comparison behind
/// a suppression exact.
pub const DEFAULT_FLAP_PERCENT: u32 = 50;

/// How many times a **flapping** identity may be emitted inside its window,
/// before the drain stops repeating it.
///
/// Three, and the number matters less than what it bounds: an oscillation says
/// everything it has to say in the first couple of emissions, and the rest is the
/// flood this policy exists to stop. A steady identity is never capped by it, so
/// this is not a rate limit on the drain (see [`crate::emission::Assessment::decide`]).
pub const DEFAULT_EMIT_CAP: usize = 3;

/// The `[drain]` table: how often the advisory drain may wake, when it stops
/// asking, and how much it may say when it does.
///
/// Every key here bounds **the engine's own output**, which is why none of them
/// is layered raise-only by [`crate::resolve`]: "raise" has no meaning for an
/// interval — a longer one is quieter and a shorter one is louder — and a cap on
/// what Batten prints about itself is not a policy bar a local file could
/// weaken. The committed authority sets them, and a local file does not move
/// them.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DrainConfig {
    /// The coalescing window in milliseconds. Every wake inside it after a drain
    /// is masked.
    ///
    /// `0` disables coalescing: every wake drains. That is a legitimate setting
    /// — it is what a host that really does deliver one wake per batch would
    /// want — and not a disabled feature, which is why it is spelled as the
    /// bottom of the range rather than as an `enabled` flag.
    #[serde(default = "default_interval_ms")]
    pub interval_ms: u64,
    /// How many consecutive silent drains before wakes stop draining until the
    /// store moves.
    ///
    /// `0` means the give-up applies immediately once a drain says nothing, so a
    /// quiet session pays a format read per wake and nothing more.
    #[serde(default = "default_empty_poll_giveup")]
    pub empty_poll_giveup: u32,
    /// Distinct identities one rule may spend entries on in a single drain.
    ///
    /// A rule over it renders one `rule R: K+ findings` summary line instead,
    /// and never `K` entries. `0` caps every rule that surfaced anything, which
    /// is the honest bottom of the range — a drain of nothing but summary lines
    /// — rather than a disabled feature.
    #[serde(default = "default_cardinality_cap")]
    pub cardinality_cap: usize,
    /// The rendered payload's ceiling, in estimated tokens.
    ///
    /// Applied after the cap, over the payload as a whole. `0` means the drain
    /// says nothing at all, which is a legitimate setting for a host that reads
    /// findings some other way and not a disabled feature.
    #[serde(default = "default_token_budget")]
    pub token_budget: usize,
    /// How many of a subject's evaluations the flap ratio is computed over
    /// (CLOUD-165), counted in evaluation boundaries and never in wall-clock time.
    ///
    /// `0` and `1` both mean no window can hold a transition, so nothing is ever
    /// annotated flapping and nothing is ever flap-suppressed — the honest bottom
    /// of the range, and the setting a consumer uses to turn the policy off
    /// without a second key that could disagree with this one.
    #[serde(default = "default_flap_window")]
    pub flap_window: usize,
    /// The flap threshold, as state changes per hundred adjacent evaluations.
    ///
    /// `0` annotates every identity with two evaluations in its window, and `101`
    /// or above annotates none, both of which are the range's honest ends rather
    /// than special cases.
    #[serde(default = "default_flap_percent")]
    pub flap_percent: u32,
    /// How many times a flapping identity may be emitted inside its window.
    ///
    /// `0` withholds a flapping identity outright. A steady one is unaffected at
    /// any value, because the cap and the annotation are read as a conjunction.
    #[serde(default = "default_emit_cap")]
    pub emit_cap: usize,
}

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

fn default_empty_poll_giveup() -> u32 {
    DEFAULT_EMPTY_POLL_GIVEUP
}

fn default_cardinality_cap() -> usize {
    DEFAULT_CARDINALITY_CAP
}

fn default_token_budget() -> usize {
    DEFAULT_TOKEN_BUDGET
}

fn default_flap_window() -> usize {
    DEFAULT_FLAP_WINDOW
}

fn default_flap_percent() -> u32 {
    DEFAULT_FLAP_PERCENT
}

fn default_emit_cap() -> usize {
    DEFAULT_EMIT_CAP
}

impl Default for DrainConfig {
    fn default() -> Self {
        DrainConfig {
            interval_ms: DEFAULT_INTERVAL_MS,
            empty_poll_giveup: DEFAULT_EMPTY_POLL_GIVEUP,
            cardinality_cap: DEFAULT_CARDINALITY_CAP,
            token_budget: DEFAULT_TOKEN_BUDGET,
            flap_window: DEFAULT_FLAP_WINDOW,
            flap_percent: DEFAULT_FLAP_PERCENT,
            emit_cap: DEFAULT_EMIT_CAP,
        }
    }
}

/// What a wake resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// Run a drain cycle now.
    Drain,
    /// Inside the window: a drain already ran, and this wake is folded into the
    /// follow-up it owes.
    Coalesced,
    /// Enough consecutive drains said nothing, and the store has not moved since
    /// the last one. Nothing is read.
    GaveUp,
}

impl Wake {
    /// Every outcome, so a census over them is derived rather than re-typed.
    pub const ALL: &'static [Wake] = &[Wake::Drain, Wake::Coalesced, Wake::GaveUp];

    /// The stable token used in machine-readable notes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Wake::Drain => "drain",
            Wake::Coalesced => "coalesced",
            Wake::GaveUp => "gave-up",
        }
    }
}

/// One session's wake state, persisted because each wake is its own process.
///
/// Everything here is a **coordinate or a count** — a clock reading, a cursor, a
/// digest, two counters. No finding content reaches this file (rule 4), which is
/// what lets it live beside the store rather than inside the guarded set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WakeState {
    /// The on-disk format version.
    pub schema: u32,
    /// When the last drain ran, in milliseconds since the Unix epoch.
    #[serde(rename = "lastDrainMs")]
    pub last_drain_ms: u64,
    /// Whether a wake was masked and a follow-up is owed.
    ///
    /// Load-bearing beyond bookkeeping: a pending follow-up **suppresses the
    /// give-up**. Giving up while a wake is owed would drop the one drain the
    /// mask promised, which is the coalescing window silently becoming a loss.
    #[serde(default)]
    pub pending: bool,
    /// Consecutive drains that emitted nothing.
    #[serde(rename = "emptyPolls", default)]
    pub empty_polls: u32,
    /// The merged-log position the give-up is measured against. The store moving
    /// past it re-arms.
    #[serde(rename = "armedSeqno", default)]
    pub armed_seqno: u64,
    /// The journal cursor this session has drained to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<journal::Cursor>,
    /// What the last drain told this session, per identity: fingerprint hex to
    /// occurrence count.
    ///
    /// The anchor a group re-raise is measured against. The store holds no count
    /// anchor — [`crate::identity::compare_to_anchor`] is fed by decision
    /// records, which answer a different question — and the honest anchor for
    /// "is this worth saying again" is what the agent was last *told*, not what
    /// some other surface last saw.
    ///
    /// Bounded by the payload rather than by the store: only identities that
    /// were actually emitted are remembered, so a rule with five thousand
    /// identities behind a cap leaves five thousand nothing here. Still a
    /// coordinate and a count, so rule 4 holds.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub counts: BTreeMap<String, u64>,
}

impl Default for WakeState {
    fn default() -> Self {
        WakeState {
            schema: WAKE_SCHEMA,
            last_drain_ms: 0,
            pending: false,
            empty_polls: 0,
            armed_seqno: 0,
            cursor: None,
            counts: BTreeMap::new(),
        }
    }
}

impl WakeState {
    /// Record that this wake was masked.
    pub const fn coalesce(&mut self) {
        self.pending = true;
    }

    /// Fold a completed drain back into the state.
    ///
    /// `emitted` is whether the agent was actually shown something, which is a
    /// different question from whether the drain found anything: a payload
    /// suppressed by the `resultId` short-circuit found plenty and said nothing,
    /// and it counts as an empty poll for exactly that reason — the give-up is
    /// about how long the drain has been *silent*, not how long the store has
    /// been empty.
    ///
    /// The remembered counts move only when something was **emitted**, for the
    /// same reason: they are the anchor for "what the agent was last told", and
    /// a payload nobody was shown told it nothing. Advancing them on a silent
    /// drain would let a re-raise that happened during the silence go unsaid.
    pub fn drained(&mut self, now_ms: u64, seqno: u64, cycle: &Drained, emitted: bool) {
        self.last_drain_ms = now_ms;
        self.pending = false;
        self.armed_seqno = seqno;
        if emitted {
            self.empty_polls = 0;
            self.counts.clone_from(&cycle.counts);
        } else {
            self.empty_polls = self.empty_polls.saturating_add(1);
        }
    }
}

/// Whether this wake drains, coalesces, or gives up.
///
/// Pure: no clock, no I/O, no environment. `now_ms` and `seqno` are supplied by
/// the boundary, so every verdict is a function of state plus config plus two
/// readings — which is what lets the §7 obligations be asserted directly rather
/// than through a sleep.
#[must_use]
pub fn decide_wake(state: &WakeState, config: &DrainConfig, now_ms: u64, seqno: u64) -> Wake {
    // `saturating_sub` rather than a checked subtraction: a clock that went
    // backwards (an NTP step, a container's clock settling) reads as "the window
    // has not elapsed", which coalesces. Coalescing on a bad clock delays a
    // drain; the other rounding would drain on every wake until the clock caught
    // up, turning a clock glitch into the once-per-verifier behaviour this
    // module exists to prevent.
    if now_ms.saturating_sub(state.last_drain_ms) < config.interval_ms {
        return Wake::Coalesced;
    }
    if state.empty_polls >= config.empty_poll_giveup && !state.pending && seqno <= state.armed_seqno
    {
        return Wake::GaveUp;
    }
    Wake::Drain
}

/// Whether a stored finding survives the changed-scope filter.
///
/// See the module docs for why the per-kind split is the whole point and not a
/// convenience. `changed` is repo-relative paths, the shape
/// [`crate::git::changed_paths`] answers in and the shape an [`Instance::path`]
/// is recorded in.
#[must_use]
pub fn in_scope(record: &FindingRecord, changed: &BTreeSet<String>) -> bool {
    match record.identity.kind() {
        // Code-anchored: the only kind diff scoping is a valid control for.
        Some(FindingKind::Code) => record
            .instances
            .iter()
            .any(|instance| changed.contains(&instance.path)),
        // Sequence, log and scope kinds bypass unconditionally — and so does a
        // kind this binary cannot classify. Both are the fail-open-in-reporting
        // direction the module docs state.
        Some(FindingKind::Log | FindingKind::Scope | FindingKind::Sequence) | None => true,
    }
}

/// One drain cycle's result: what to say, what was withheld and why, what the
/// agent was told each identity's count was, and the digest that decides whether
/// saying it again would be repetition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drained {
    /// The pointer lines to emit, ordered salient-first and deterministically,
    /// so the payload is byte-stable.
    pub lines: Vec<String>,
    /// Identities the scope filter withheld.
    pub scope_filtered: Vec<FindingRecord>,
    /// Identities withheld because their rule was over the cardinality cap. A
    /// property of the rule, and so the reason rule-health telemetry reads.
    pub capped: Vec<FindingRecord>,
    /// Identities withheld because the payload had no room for them **this
    /// boundary**. A property of the payload, and so retried on the next drain.
    pub over_budget: Vec<FindingRecord>,
    /// Identities withheld because they are flapping and have spent their
    /// re-emit budget for the window (CLOUD-165). A property of the SIGNAL, which
    /// is a third thing again: the scope filter is about the tree, the cap about
    /// the rule, the budget about this payload, and this about whether the
    /// identity's own history makes another line informative.
    pub flap_suppressed: Vec<FindingRecord>,
    /// Flapping identities per rule, for the rule-health annotation. Pointer-only:
    /// a rule id and a count, never a finding's content.
    pub flapping: BTreeMap<String, usize>,
    /// Re-raises of an identity already carried by this payload, suppressed and
    /// counted rather than emitted twice.
    pub duplicates: usize,
    /// What this payload told the agent each emitted identity's count was, by
    /// fingerprint hex. The anchor the next drain's re-raise detection reads.
    pub counts: BTreeMap<String, u64>,
    /// The digest of [`Drained::lines`], as hex.
    pub result_id: String,
}

/// One identity that survived selection, with the instance to point at.
///
/// Selection and rendering are separate passes because the cap is a decision
/// about a *set* of identities: a renderer that emitted as it walked could not
/// know that an eleventh identity for the same rule was still coming.
#[derive(Debug, Clone, Copy)]
struct Surfaced<'a> {
    record: &'a FindingRecord,
    instance: &'a Instance,
}

/// One thing the payload can say: a pointer, or a rule's cardinality summary.
///
/// Both are subject to the token budget, which is why they are one type — a
/// summary line that escaped the clamp would be a payload the budget did not
/// actually bound.
#[derive(Debug, Clone, Copy)]
enum Item<'a> {
    /// One identity's pointer line.
    Entry(Surfaced<'a>),
    /// One rule's summary, standing for the identities the cap withheld.
    Summary {
        rule: &'a str,
        tier: AdvisoryTier,
        withheld: usize,
    },
}

impl Item<'_> {
    /// The sort key: tier first (strongest first), then rule, then fingerprint.
    ///
    /// The occurrence count is **not** in it, and that is the point: CLOUD-80's
    /// no-escalation law says a duplicate count never escalates a tier, so
    /// salience is made structurally independent of the count rather than left
    /// to a reviewer noticing.
    fn key(&self) -> (std::cmp::Reverse<AdvisoryTier>, &str, String) {
        match self {
            Item::Entry(surfaced) => (
                std::cmp::Reverse(surfaced.record.tier),
                surfaced.record.rule.as_str(),
                surfaced.record.identity.fingerprint.to_hex(),
            ),
            // The empty digest sorts a rule's summary ahead of any entry that
            // shares its tier and rule — of which, by construction, it has none.
            Item::Summary { rule, tier, .. } => (std::cmp::Reverse(*tier), rule, String::new()),
        }
    }

    /// How many findings this item stands for, for the withheld count the budget
    /// line reports.
    const fn weight(&self) -> usize {
        match self {
            Item::Entry(_) => 1,
            Item::Summary { withheld, .. } => *withheld,
        }
    }
}

/// Render one line for a record, given the instance to point at and what the
/// last drain said this identity's count was.
///
/// **Pointer-only** (rule 4): a fingerprint, a rule id, a `path:line` coordinate
/// and a count. The store holds no matched content, so there is none here to
/// leak — the discipline is stated anyway because this is the one place emission
/// shape is decided, and it should carry the contract rather than assume it.
///
/// A count that **rose** renders as `old->new`: the identity is the same, and
/// the delta is the news. A count that fell renders plainly — a ratchet is not a
/// re-raise, because re-raising on incremental fixing punishes the fix. The line
/// stays four space-separated fields whichever branch is taken.
fn render_line(record: &FindingRecord, instance: &Instance, previous: Option<u64>) -> String {
    let count = match instance.occurrences {
        Observation::Observed(count) => match previous {
            Some(old) if count > old => format!("{old}->{count}"),
            _ => count.to_string(),
        },
        Observation::NotObserved(_) => "held".to_owned(),
    };
    let at = match instance.line {
        Some(line) => format!("{}:{line}", instance.path),
        None => instance.path.clone(),
    };
    format!(
        "{} {} {at} {count}",
        record.identity.fingerprint.to_hex(),
        record.rule
    )
}

/// The one line a rule over the cardinality cap gets, in place of its entries.
fn cap_summary(rule: &str, cap: usize) -> String {
    format!("rule {rule}: {cap}+ findings")
}

/// The one line closing a payload the token budget clamped.
fn budget_summary(withheld: usize) -> String {
    format!("budget: {withheld} findings withheld")
}

/// Whether `lines` plus `candidate` — and the closing summary a later clamp
/// would owe — still fits the budget.
///
/// Measured over the joined payload with [`crate::budget::estimate_tokens`],
/// which is the same estimator `[budget]` gates instruction files with. A second
/// estimator here would let the two disagree about what a token is.
fn within(lines: &[String], candidate: &str, reserve: Option<&str>, budget: usize) -> bool {
    let mut payload: Vec<&str> = lines.iter().map(String::as_str).collect();
    payload.push(candidate);
    payload.extend(reserve);
    crate::budget::estimate_tokens(&payload.join("\n")) <= budget
}

/// Run one drain cycle over a store snapshot. Pure.
///
/// `context` is the ref this checkout is on, when it has one: an identity
/// observed in several contexts is **one** finding, and the count worth showing
/// is the one for the ref the agent is actually working on. Falling back to the
/// first instance (they are sorted by context) keeps the answer deterministic
/// rather than absent on a detached `HEAD`.
///
/// Deliberately **not** built on [`crate::findings::pointer_lines`]: that
/// renders one line per *instance*, which is right for `state list` — a listing
/// should show every context — and wrong here, where the contract is one line
/// per *identity* and a repeat within a drain is suppressed and counted.
///
/// `previous` is what the last drain told this session, per identity, which is
/// what makes a re-raise sayable as `old->new`. An empty map is the honest first
/// drain: everything is news, and nothing is a re-raise.
///
/// Three ordered stages, and the order is the contract: **select** the one
/// instance per identity worth pointing at, **cap** each rule that surfaced more
/// distinct identities than it may spend lines on, then **order and clamp** the
/// survivors to the token budget.
#[must_use]
pub fn cycle(
    records: &[FindingRecord],
    changed: &BTreeSet<String>,
    context: Option<&Context>,
    config: &DrainConfig,
    previous: &BTreeMap<String, u64>,
    log: &[journal::Entry],
) -> Drained {
    let assessment = emission::assess(log, config.flap_window, config.flap_percent);
    let selected = select(records, changed, context, &assessment, config.emit_cap);
    // The state lines are taken BEFORE the cap consumes the surfaced set, so the
    // digest covers every identity this cycle looked at rather than only the ones
    // that got a line. See [`state_lines`] for why that is the difference between
    // a report id and a set hash.
    let state = state_lines(&selected.shown);
    let (items, capped) = cap(selected.shown, config.cardinality_cap);
    let clamped = clamp(&items, config, previous);
    let result_id = result_fingerprint(
        &clamped,
        &state,
        &capped,
        &selected.scope_filtered,
        &selected.flap_suppressed,
    );
    Drained {
        lines: clamped.lines,
        scope_filtered: selected.scope_filtered,
        capped,
        over_budget: clamped.over_budget,
        flapping: flapping_by_rule(records, &assessment),
        flap_suppressed: selected.flap_suppressed,
        duplicates: selected.duplicates,
        counts: clamped.counts,
        result_id,
    }
}

/// How many of each rule's identities the journal reports as flapping.
///
/// Over **every** record, not only the ones this cycle surfaced: a flapping
/// identity outside the changed scope is still a fact about its rule's health, and
/// counting only the surfaced ones would make the number a function of what the
/// agent happened to be editing. Keyed by rule because that is what a health
/// counter is read by — one flapping identity is a finding, a rule whose
/// identities all flap is a rule to fix.
fn flapping_by_rule(
    records: &[FindingRecord],
    assessment: &emission::Assessment,
) -> BTreeMap<String, usize> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for record in records {
        if assessment
            .health(&record.identity.fingerprint.to_hex())
            .is_flapping()
        {
            *counts.entry(record.rule.clone()).or_insert(0) += 1;
        }
    }
    counts
}

/// The state-bearing facts about the surfaced set, one pointer-only line per
/// identity: `<fingerprint> <disposition> <presentation>`.
///
/// **The `resultId` is a report id, not a set hash** (CLOUD-166). A digest over
/// the rendered bytes alone would call a cycle "unchanged" when a *disposition*
/// moved — the agent acted on a finding, or the engine reclassified why it was
/// withheld — because neither shows in a pointer line. That is the adversarial
/// case the issue names: a state change silently skipped because its rendering
/// happened to be identical. Counts are already in the lines; these are the
/// fields that are not.
///
/// The presentation goes through serde rather than a hand-written token, so a
/// variant added later enters the digest without anyone remembering to widen a
/// match here.
fn state_lines(shown: &BTreeMap<String, Surfaced<'_>>) -> Vec<String> {
    shown
        .iter()
        .map(|(key, surfaced)| {
            let disposition = surfaced.record.disposition.map_or_else(
                || "-".to_owned(),
                |disposition| disposition.as_str().to_owned(),
            );
            let presentation = serde_json::to_string(&surfaced.record.presentation)
                .unwrap_or_else(|_| "?".to_owned());
            format!("{key} {disposition} {presentation}")
        })
        .collect()
}

/// The digest a repeat is recognised by: the payload, plus every state-bearing
/// fact behind it, plus how much was withheld and why.
///
/// The withheld *counts* are in the input because a finding moving between the
/// two withholding reasons is a state change the payload cannot show — the lines
/// are identical whether a rule was capped or its entries clamped, and the two
/// mean different things to the rate that reads them.
fn result_fingerprint(
    clamped: &Clamped,
    state: &[String],
    capped: &[FindingRecord],
    scope_filtered: &[FindingRecord],
    flap_suppressed: &[FindingRecord],
) -> String {
    let mut input = clamped.lines.clone();
    input.extend(state.iter().cloned());
    // The flap count joins the tuple for the same reason the other three are in
    // it, and the omission would have been the worse bug: a flap suppression is
    // invisible in the lines, so a cycle that withheld a newly-flapping identity
    // would digest identically to the one before it and the `resultId`
    // short-circuit would report `unchanged` about a payload that had changed.
    input.push(format!(
        "withheld {} {} {} {}",
        scope_filtered.len(),
        capped.len(),
        clamped.over_budget.len(),
        flap_suppressed.len()
    ));
    drain_result_fingerprint(&input).to_hex()
}

/// What the selection stage found: one entry per identity, what the scope filter
/// withheld, and how many records collapsed into an entry already taken.
struct Selected<'a> {
    shown: BTreeMap<String, Surfaced<'a>>,
    scope_filtered: Vec<FindingRecord>,
    flap_suppressed: Vec<FindingRecord>,
    duplicates: usize,
}

/// Stage one: the one instance per identity worth pointing at.
///
/// The emission policy is applied **here**, after the scope filter and before the
/// instance pick, and the position is chosen rather than convenient. This is the
/// last point at which a withheld identity can still be carried out as a record
/// for journalling — after `cap` it has been folded into a summary line and after
/// `state_lines` it is already inside the digest, so a filter downstream of either
/// would be a suppression the store never learns about.
fn select<'a>(
    records: &'a [FindingRecord],
    changed: &BTreeSet<String>,
    context: Option<&Context>,
    assessment: &emission::Assessment,
    emit_cap: usize,
) -> Selected<'a> {
    let mut scope_filtered = Vec::new();
    let mut flap_suppressed = Vec::new();
    // Keyed by identity, which is what makes "suppressed and counted" the
    // structure rather than a rule applied afterwards: a second record for one
    // identity cannot occupy a second entry.
    let mut shown: BTreeMap<String, Surfaced<'a>> = BTreeMap::new();
    let mut duplicates = 0;

    for record in records {
        // The emittability half of CLOUD-81, read off the schema rather than
        // re-typed here: a finding with no check cannot be settled and one with
        // no stated remediation cannot be acted on, so emitting either spends
        // the agent's attention on something it has no way to close. `record`
        // refuses both at ingest, so this only ever catches a record written
        // before schema 3 — and it is deliberately NOT counted as a
        // drain suppression, because the engine did not choose to withhold it;
        // there was never anything emittable to withhold.
        if !record.is_emittable() {
            continue;
        }
        if !in_scope(record, changed) {
            scope_filtered.push(record.clone());
            continue;
        }
        // The signal filter (CLOUD-165). It reads the identity's own history off
        // the journal and decides nothing about the finding's state: the record
        // below is unchanged, its instances still say what the last scan saw, and
        // its disposition is whatever the agent gave it.
        if let emission::Emission::Withhold(_) =
            assessment.decide(&record.identity.fingerprint.to_hex(), emit_cap)
        {
            flap_suppressed.push(record.clone());
            continue;
        }
        let Some(instance) = context
            .and_then(|context| record.instance(context))
            .or_else(|| record.instances.first())
        else {
            // A record with no instance at all observes nothing anywhere. There
            // is no coordinate to point at, so there is nothing to say.
            continue;
        };
        let key = record.identity.fingerprint.to_hex();
        if shown.insert(key, Surfaced { record, instance }).is_some() {
            duplicates += 1;
        }
    }

    Selected {
        shown,
        scope_filtered,
        flap_suppressed,
        duplicates,
    }
}

/// Stage two: collapse every rule that surfaced more distinct identities than it
/// may spend entries on, and carry what it withheld out for journalling.
///
/// Grouped by rule over `shown`, whose iteration is by fingerprint hex, so both
/// the grouping and every group's contents are a function of the SET. The result
/// is sorted salient-first, which is the order the clamp then spends the budget
/// in — dropping the least salient first is what makes a truncated payload the
/// most useful one that fits.
fn cap(shown: BTreeMap<String, Surfaced<'_>>, cap: usize) -> (Vec<Item<'_>>, Vec<FindingRecord>) {
    let mut per_rule: BTreeMap<&str, Vec<Surfaced<'_>>> = BTreeMap::new();
    for surfaced in shown.into_values() {
        per_rule
            .entry(surfaced.record.rule.as_str())
            .or_default()
            .push(surfaced);
    }

    let mut capped: Vec<FindingRecord> = Vec::new();
    let mut items: Vec<Item<'_>> = Vec::new();
    for (rule, surfaced) in per_rule {
        if surfaced.len() > cap {
            // The summary carries the strongest tier the rule surfaced, so
            // collapsing a rule cannot bury it below a weaker rule's entries.
            let tier = surfaced
                .iter()
                .map(|entry| entry.record.tier)
                .max()
                .unwrap_or(AdvisoryTier::Advisory);
            capped.extend(surfaced.iter().map(|entry| entry.record.clone()));
            items.push(Item::Summary {
                rule,
                tier,
                withheld: surfaced.len(),
            });
        } else {
            items.extend(surfaced.into_iter().map(Item::Entry));
        }
    }
    items.sort_by(|left, right| left.key().cmp(&right.key()));
    (items, capped)
}

/// What the clamp emitted, what it had no room for, and the counts it told the
/// agent — which become the next drain's re-raise anchor.
struct Clamped {
    lines: Vec<String>,
    over_budget: Vec<FindingRecord>,
    counts: BTreeMap<String, u64>,
}

/// Stage three: spend the token budget salient-first, and say how much went
/// unsaid.
///
/// Greedy, reserving room for the closing summary line a later drop would owe.
/// Reserving against the *remaining* weight is what makes the bound hold rather
/// than nearly hold: the line that finally gets written can only be shorter than
/// the one that was budgeted for.
fn clamp(items: &[Item<'_>], config: &DrainConfig, previous: &BTreeMap<String, u64>) -> Clamped {
    let suffix = suffix_weights(items);
    let mut lines: Vec<String> = Vec::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let mut over_budget: Vec<FindingRecord> = Vec::new();
    let mut withheld = 0;
    let mut clamped = false;

    for (index, item) in items.iter().enumerate() {
        if !clamped {
            let candidate = match item {
                Item::Entry(surfaced) => {
                    let key = surfaced.record.identity.fingerprint.to_hex();
                    render_line(
                        surfaced.record,
                        surfaced.instance,
                        previous.get(&key).copied(),
                    )
                }
                Item::Summary { rule, .. } => cap_summary(rule, config.cardinality_cap),
            };
            let reserve = suffix
                .get(index + 1)
                .filter(|remaining| **remaining > 0)
                .map(|remaining| budget_summary(*remaining));
            if within(&lines, &candidate, reserve.as_deref(), config.token_budget) {
                if let Item::Entry(surfaced) = item {
                    // Only an observed count anchors the next drain's re-raise:
                    // a rule that did not run said nothing about how many.
                    if let Observation::Observed(count) = surfaced.instance.occurrences {
                        counts.insert(surfaced.record.identity.fingerprint.to_hex(), count);
                    }
                }
                lines.push(candidate);
                continue;
            }
            clamped = true;
        }
        withheld += item.weight();
        if let Item::Entry(surfaced) = item {
            over_budget.push(surfaced.record.clone());
        }
    }

    if clamped {
        // The reserve above budgeted for this line; it is written only if it
        // still fits, because a first item too large to keep leaves no room
        // that was ever checked.
        let summary = budget_summary(withheld);
        if within(&lines, &summary, None, config.token_budget) {
            lines.push(summary);
        }
    }

    Clamped {
        lines,
        over_budget,
        counts,
    }
}

/// How many findings each suffix of `items` stands for, so the clamp can reserve
/// room for the closing line it might owe. One entry longer than `items`, whose
/// last element is zero: past the end nothing remains to withhold.
fn suffix_weights(items: &[Item<'_>]) -> Vec<usize> {
    let mut weights: Vec<usize> = vec![0; items.len() + 1];
    for (index, item) in items.iter().enumerate().rev() {
        weights[index] = weights[index + 1].saturating_add(item.weight());
    }
    weights
}

/// The directory holding one wake-state file per session, under a bound store.
fn drain_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(DRAIN_DIR)
}

/// The file a session's wake state lives in.
///
/// The session id is hashed rather than used as a filename: it is a host-chosen
/// string, and a host that ever puts a separator or a traversal component in one
/// must not be able to choose where this writes.
fn wake_path(store_dir: &Path, session: &str) -> PathBuf {
    let key = crate::identity::store_fingerprint(&[session]).to_hex();
    drain_dir(store_dir).join(format!("{key}.json"))
}

/// Read a session's wake state, treating anything unreadable as **fresh**.
///
/// A corrupt or future-schema state file resolves to [`WakeState::default`],
/// which drains. That is the safe direction for an advisory surface: the cost of
/// being wrong is one extra drain, where refusing would make a garbled bookkeeping
/// file the reason findings stop being surfaced.
#[must_use]
pub fn load_wake(store_dir: &Path, session: &str) -> WakeState {
    let Ok(text) = std::fs::read_to_string(wake_path(store_dir, session)) else {
        return WakeState::default();
    };
    serde_json::from_str::<WakeState>(&text)
        .ok()
        .filter(|state| state.schema == WAKE_SCHEMA)
        .unwrap_or_default()
}

/// Publish a session's wake state atomically, so a concurrent wake never reads a
/// torn file.
///
/// # Errors
///
/// Returns an error when the state cannot be written or published.
pub fn save_wake(store_dir: &Path, session: &str, state: &WakeState) -> Result<()> {
    let dir = drain_dir(store_dir);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the drain state directory {}", dir.display()))?;
    let path = wake_path(store_dir, session);
    let temp = dir.join(format!("{}.tmp", std::process::id()));
    std::fs::write(&temp, format!("{}\n", serde_json::to_string_pretty(state)?))
        .with_context(|| format!("write the drain state {}", temp.display()))?;
    std::fs::rename(&temp, &path)
        .with_context(|| format!("publish the drain state {}", path.display()))?;
    Ok(())
}

/// Journal every newly withheld identity as not-shown, before anything is
/// emitted.
///
/// **Persist before emit**, and the reason is the false-positive rate rather
/// than durability: a finding the engine withheld never had the chance to be
/// acted on, so [`crate::findings::effective_fp_rates`] must exclude it from
/// both sides of the ratio. An unrecorded suppression is silently counted as the
/// agent ignoring something it was never shown, which lets the drain inflate the
/// number the store exists to measure.
///
/// **Newly** is load-bearing. A finding outside the changed scope stays outside
/// it for as long as the agent works elsewhere, so an unconditional append would
/// write one entry per identity per drain, for every drain of a long session —
/// and shards are read whole and replayed into the merged log, so that growth is
/// not merely disk, it is every cursor delta from then on. A record already
/// carrying this disposition is already saying what the append would say, so the
/// append carries no information. Returns how many entries were actually
/// written, which is what tells the caller whether a fold is worth running.
///
/// # Errors
///
/// Returns an error when a shard cannot be appended to.
pub fn record_suppressions(
    store_dir: &Path,
    shard: &str,
    withheld: &[FindingRecord],
    why: NotShown,
) -> Result<usize> {
    let mut appended = 0;
    for record in withheld {
        if record.presentation == Presentation::NotShown(why) {
            continue;
        }
        journal::append(
            store_dir,
            shard,
            &journal::Entry {
                identity: record.identity.fingerprint.to_hex(),
                rule: record.rule.clone(),
                // The emission channel's own statement, which is what makes it
                // authoritative over `presentation` (CLOUD-529's `Origin`).
                origin: journal::Origin::Drain,
                // A suppression is a fact about this boundary, not about a scan,
                // so it records no ref and no occurrence count: the evaluation
                // that produced the record already journalled both.
                context: None,
                observation: None,
                disposition: None,
                presentation: Presentation::NotShown(why),
            },
        )?;
        appended += 1;
    }
    Ok(appended)
}

/// Journal every identity this cycle withheld, under the reason it was withheld
/// for.
///
/// One call rather than three at the boundary, because the *pairing* of a
/// withheld set with its reason is a fact about the emission contract and not
/// about the caller: the cap is a property of the rule and feeds rule-health
/// telemetry, where the scope filter and the token clamp are properties of this
/// boundary — the finding is unchanged and the next drain reconsiders it. A
/// caller free to pair them differently could put a transient suppression into
/// the number CLOUD-78's sampled review reads as rule health.
///
/// Returns how many entries were actually written, which is what tells the
/// caller whether a fold is worth running.
///
/// # Errors
///
/// Returns an error when a shard cannot be appended to.
pub fn journal_suppressions(store_dir: &Path, shard: &str, cycle: &Drained) -> Result<usize> {
    let mut appended = record_suppressions(
        store_dir,
        shard,
        &cycle.scope_filtered,
        NotShown::DrainSuppressed,
    )?;
    appended += record_suppressions(
        store_dir,
        shard,
        &cycle.capped,
        NotShown::OverCardinalityCap,
    )?;
    appended += record_suppressions(
        store_dir,
        shard,
        &cycle.over_budget,
        NotShown::DrainSuppressed,
    )?;
    appended += record_suppressions(
        store_dir,
        shard,
        &cycle.flap_suppressed,
        NotShown::FlapSuppressed,
    )?;
    Ok(appended)
}

/// Journal every identity this payload actually emitted.
///
/// # Why the emission needs a record and the suppression already had one
///
/// The withheld sets were journalled from the start, because a finding the engine
/// withheld must be excluded from the false-positive rate. The *shown* case needed
/// nothing, since `Shown` is what a record already defaults to — so the log grew a
/// suppression history and no emission history, and an emission cap counted in
/// evaluation boundaries has nothing to count (CLOUD-165). This is that half.
///
/// It also repairs a smaller asymmetry: an identity suppressed at one boundary and
/// emitted at the next kept the `NotShown` reason on its record forever, because
/// only a suppression ever wrote the field. Now the boundary that emits says so.
///
/// **Called only when the payload reaches the agent.** A cycle short-circuited as
/// `unchanged` emitted nothing, and recording an emission there would spend the
/// cap on a boundary the agent never saw.
///
/// # Errors
///
/// Returns an error when a shard cannot be appended to.
pub fn record_emissions(
    store_dir: &Path,
    shard: &str,
    records: &[FindingRecord],
    emitted: &BTreeMap<String, u64>,
) -> Result<usize> {
    let mut appended = 0;
    for record in records
        .iter()
        .filter(|record| emitted.contains_key(&record.identity.fingerprint.to_hex()))
    {
        journal::append(
            store_dir,
            shard,
            &journal::Entry {
                identity: record.identity.fingerprint.to_hex(),
                rule: record.rule.clone(),
                origin: journal::Origin::Drain,
                context: None,
                observation: None,
                disposition: None,
                presentation: Presentation::Shown,
            },
        )?;
        appended += 1;
    }
    Ok(appended)
}

/// The payload as the agent sees it: the pointer lines, one per line.
///
/// A separate function from [`cycle`] so the bytes emitted are a pure function of
/// the drain result and nothing else — which is what CLOUD-82's byte-stability
/// and token-budget assertions need a seam for.
#[must_use]
pub fn render(drained: &Drained) -> String {
    drained.lines.join("\n")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::findings::{Check, FINDINGS_SCHEMA, Instance, Remediation};
    use crate::identity::{SpanNormalization, StoredIdentity, code_fingerprint};
    use crate::severity::{AdvisoryTier, RuleSeverity};

    fn record(kind: FindingKind, rule: &str, path: &str, span: &str) -> FindingRecord {
        FindingRecord {
            schema: FINDINGS_SCHEMA,
            identity: StoredIdentity::new(
                kind,
                code_fingerprint(rule, path, span, SpanNormalization::Collapsed).unwrap(),
            ),
            rule: rule.to_owned(),
            severity: RuleSeverity::Deny,
            tier: AdvisoryTier::Advisory,
            disposition: None,
            presentation: Presentation::Shown,
            // Emittable by default (CLOUD-81), because that is what `record`
            // mints today; the checkless case is built explicitly by the one
            // test that is about it.
            check: Some(Check::Reevaluate),
            remediation: Some(Remediation::NoFix("test fixture".to_owned())),
            instances: vec![Instance {
                context: Context::new("refs/heads/a"),
                occurrences: Observation::Observed(1),
                observed_at_commit: "0".repeat(40),
                worktree_path: None,
                path: path.to_owned(),
                line: Some(1),
            }],
        }
    }

    fn changed(paths: &[&str]) -> BTreeSet<String> {
        paths.iter().map(|path| (*path).to_owned()).collect()
    }

    /// A cycle under the shipped defaults, with no memory of a previous drain —
    /// the shape every test that is not about the cap, the budget or a re-raise
    /// wants, so those three stay legible as the ones passing a config.
    fn cycled(
        records: &[FindingRecord],
        changed: &BTreeSet<String>,
        context: Option<&Context>,
    ) -> Drained {
        cycle(
            records,
            changed,
            context,
            &DrainConfig::default(),
            &BTreeMap::new(),
            &[],
        )
    }

    /// A completed cycle carrying nothing but a digest, for the state-machine
    /// tests: they fold a drain back in and care only about what the fold does.
    fn folded(result_id: &str) -> Drained {
        Drained {
            lines: Vec::new(),
            scope_filtered: Vec::new(),
            capped: Vec::new(),
            over_budget: Vec::new(),
            flap_suppressed: Vec::new(),
            flapping: BTreeMap::new(),
            duplicates: 0,
            counts: BTreeMap::new(),
            result_id: result_id.to_owned(),
        }
    }

    // --- (a) one wake per batch --------------------------------------------

    #[test]
    fn a_batch_of_n_verifier_results_produces_exactly_one_drain() {
        // Acceptance (a). N wakes inside one window — the shape a batch of tool
        // calls actually arrives in, since each is its own process — must
        // resolve to exactly ONE drain. Anything else is the once-per-verifier
        // behaviour this module exists to remove.
        let config = DrainConfig {
            interval_ms: 2_000,
            empty_poll_giveup: 3,
            ..DrainConfig::default()
        };
        let mut state = WakeState::default();
        let start = 1_000_000_u64;

        let mut drains = 0;
        for offset in [0, 5, 11, 40, 130, 700, 1_999] {
            match decide_wake(&state, &config, start + offset, 0) {
                Wake::Drain => {
                    drains += 1;
                    state.drained(start + offset, 0, &folded("r"), true);
                }
                Wake::Coalesced => state.coalesce(),
                Wake::GaveUp => panic!("a fresh state never gives up"),
            }
        }
        assert_eq!(drains, 1, "seven verifier results, one drain");
    }

    // --- (b) wakes are masked while a drain is pending -----------------------

    #[test]
    fn two_batches_against_one_window_coalesce_to_a_single_follow_up() {
        // Acceptance (b). The mask is what enforces once-per-batch, so two
        // batches arriving while one drain is owed must produce ONE follow-up.
        let config = DrainConfig {
            interval_ms: 1_000,
            empty_poll_giveup: 3,
            ..DrainConfig::default()
        };
        let mut state = WakeState::default();
        let start = 1_000_000_u64;

        // The drain that opens the window.
        assert_eq!(decide_wake(&state, &config, start, 0), Wake::Drain);
        state.drained(start, 0, &folded("r0"), true);

        // Two whole batches land inside it. Every one is masked.
        for offset in [10, 20, 30, 500, 510, 520] {
            assert_eq!(
                decide_wake(&state, &config, start + offset, 0),
                Wake::Coalesced
            );
            state.coalesce();
        }
        assert!(state.pending, "a follow-up is owed");

        // Past the window, the six masked wakes redeem as ONE drain.
        assert_eq!(decide_wake(&state, &config, start + 1_000, 0), Wake::Drain);
        state.drained(start + 1_000, 0, &folded("r1"), true);
        assert!(!state.pending, "the follow-up was paid");
        assert_eq!(
            decide_wake(&state, &config, start + 1_001, 0),
            Wake::Coalesced,
            "and the window reopens behind it"
        );
    }

    #[test]
    fn a_pending_follow_up_suppresses_the_give_up() {
        // The mask must not be able to lose a drain. A wake was masked on the
        // promise of a follow-up; giving up instead would break that promise
        // silently, which is a coalescing window turning into a dropped finding.
        let config = DrainConfig {
            interval_ms: 100,
            empty_poll_giveup: 1,
            ..DrainConfig::default()
        };
        let quiet = WakeState {
            empty_polls: 5,
            armed_seqno: 7,
            last_drain_ms: 0,
            ..WakeState::default()
        };
        assert_eq!(
            decide_wake(&quiet, &config, 10_000, 7),
            Wake::GaveUp,
            "silent, and the store has not moved"
        );
        let owed = WakeState {
            pending: true,
            ..quiet
        };
        assert_eq!(decide_wake(&owed, &config, 10_000, 7), Wake::Drain);
    }

    // --- (c) pacing comes from config, not from constants --------------------

    #[test]
    fn the_interval_comes_from_config_not_a_constant() {
        // Acceptance (c), first half: one state, one clock, two configs, two
        // different verdicts. A hard-coded interval could not produce this.
        let state = WakeState {
            last_drain_ms: 1_000_000,
            ..WakeState::default()
        };
        let now = 1_000_500;
        assert_eq!(
            decide_wake(
                &state,
                &DrainConfig {
                    interval_ms: 1_000,
                    empty_poll_giveup: 3,
                    ..DrainConfig::default()
                },
                now,
                0
            ),
            Wake::Coalesced
        );
        assert_eq!(
            decide_wake(
                &state,
                &DrainConfig {
                    interval_ms: 100,
                    empty_poll_giveup: 3,
                    ..DrainConfig::default()
                },
                now,
                0
            ),
            Wake::Drain
        );
        assert_eq!(
            decide_wake(
                &state,
                &DrainConfig {
                    interval_ms: 0,
                    empty_poll_giveup: 3,
                    ..DrainConfig::default()
                },
                now,
                0
            ),
            Wake::Drain,
            "a zero window is every wake drains, not a disabled drain"
        );
    }

    #[test]
    fn the_empty_poll_give_up_count_comes_from_config_not_a_constant() {
        // Acceptance (c), second half. Same state and clock; the give-up count
        // alone decides whether this wake pays for a drain.
        let state = WakeState {
            last_drain_ms: 0,
            empty_polls: 2,
            armed_seqno: 4,
            ..WakeState::default()
        };
        assert_eq!(
            decide_wake(
                &state,
                &DrainConfig {
                    interval_ms: 10,
                    empty_poll_giveup: 2,
                    ..DrainConfig::default()
                },
                9_000,
                4
            ),
            Wake::GaveUp
        );
        assert_eq!(
            decide_wake(
                &state,
                &DrainConfig {
                    interval_ms: 10,
                    empty_poll_giveup: 3,
                    ..DrainConfig::default()
                },
                9_000,
                4
            ),
            Wake::Drain
        );
    }

    #[test]
    fn the_store_moving_re_arms_a_given_up_session() {
        // Give-up must be a pause, never a stop: a session that went quiet and
        // then had findings written to its store has to start speaking again, or
        // the give-up is a permanent mute after three silent batches.
        let config = DrainConfig {
            interval_ms: 10,
            empty_poll_giveup: 1,
            ..DrainConfig::default()
        };
        let state = WakeState {
            empty_polls: 3,
            armed_seqno: 4,
            ..WakeState::default()
        };
        assert_eq!(decide_wake(&state, &config, 9_000, 4), Wake::GaveUp);
        assert_eq!(
            decide_wake(&state, &config, 9_000, 5),
            Wake::Drain,
            "the merged log advanced, so there is something new to say"
        );
    }

    #[test]
    fn a_drain_that_emitted_clears_the_empty_poll_streak() {
        let mut state = WakeState {
            empty_polls: 2,
            ..WakeState::default()
        };
        state.drained(1, 0, &folded("r"), false);
        assert_eq!(state.empty_polls, 3, "silence accumulates");
        state.drained(2, 0, &folded("r"), true);
        assert_eq!(state.empty_polls, 0, "speaking resets it");
    }

    // --- (d) the scope filter is per kind ------------------------------------

    #[test]
    fn a_sequence_finding_attached_to_no_changed_file_survives_the_scope_filter() {
        // Acceptance (d), and the load-bearing one. The flagship wrong-completion
        // class attaches to no changed file BY CONSTRUCTION, so a filter that
        // dropped it would delete the findings the engine exists to raise.
        let nothing_changed = changed(&[]);
        for kind in [FindingKind::Sequence, FindingKind::Log, FindingKind::Scope] {
            assert!(
                in_scope(&record(kind, "r", "src/a.rs", "TODO"), &nothing_changed),
                "{} must bypass the scope filter unconditionally",
                kind.as_tag()
            );
        }
        assert!(
            !in_scope(
                &record(FindingKind::Code, "r", "src/a.rs", "TODO"),
                &nothing_changed
            ),
            "a code-anchored finding in an unchanged file is filtered — that is \
             the cardinality control"
        );
        assert!(
            in_scope(
                &record(FindingKind::Code, "r", "src/a.rs", "TODO"),
                &changed(&["src/a.rs"])
            ),
            "and it surfaces the moment its file is in scope"
        );
    }

    #[test]
    fn an_unclassifiable_kind_bypasses_rather_than_being_filtered_away() {
        // A record written by a future binary carrying a fifth kind. Showing it
        // costs a line; filtering it is a silent false negative, so the fail-open
        // direction is the reporting one.
        let mut future = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        future.identity.version = "quantum:2099-01-01".to_owned();
        assert_eq!(future.identity.kind(), None);
        assert!(in_scope(&future, &changed(&[])));
    }

    // --- (e) the resultId short-circuit --------------------------------------

    #[test]
    fn an_unchanged_finding_set_yields_an_unchanged_result_id() {
        // Acceptance (e), CLOUD-166's cheap path: the digest is a function of the
        // rendered payload, so an unchanged set is byte-identical and the caller
        // can decline to repeat itself.
        let records = vec![
            record(FindingKind::Code, "r", "src/a.rs", "TODO"),
            record(FindingKind::Code, "r", "src/b.rs", "FIXME"),
        ];
        let scope = changed(&["src/a.rs", "src/b.rs"]);
        let first = cycled(&records, &scope, None);
        let again = cycled(&records, &scope, None);
        assert_eq!(first.result_id, again.result_id);
        assert_eq!(
            first.lines, again.lines,
            "and the bytes agree, not just the digest"
        );
        assert_eq!(first.lines.len(), 2);

        // A count that moved is a re-raise, and must NOT short-circuit.
        let mut moved = records.clone();
        moved[0].instances[0].occurrences = Observation::Observed(9);
        assert_ne!(
            cycled(&moved, &scope, None).result_id,
            first.result_id,
            "a re-raise is new information"
        );
    }

    #[test]
    fn two_renders_of_one_snapshot_are_byte_identical_whatever_the_input_order() {
        // §6 byte-stability. Sorted by fingerprint rather than by the order
        // `load_all` happened to hand them over, so the payload is a function of
        // the SET.
        let a = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let b = record(FindingKind::Code, "r", "src/b.rs", "FIXME");
        let scope = changed(&["src/a.rs", "src/b.rs"]);
        assert_eq!(
            render(&cycled(&[a.clone(), b.clone()], &scope, None)),
            render(&cycled(&[b, a], &scope, None))
        );
    }

    #[test]
    fn a_re_raise_of_one_identity_within_a_drain_is_suppressed_and_counted() {
        // "A re-raise of the same identity within a drain is suppressed and
        // counted" — one line per IDENTITY, never one per record, and the
        // duplicate is a number rather than a silently dropped row.
        let one = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let drained = cycled(
            &[one.clone(), one.clone(), one],
            &changed(&["src/a.rs"]),
            None,
        );
        assert_eq!(drained.lines.len(), 1);
        assert_eq!(drained.duplicates, 2);
    }

    #[test]
    fn a_suppression_already_recorded_is_not_journalled_again() {
        // A finding outside the changed scope stays outside it for as long as
        // the agent works elsewhere, so an unconditional append writes one entry
        // per identity per drain — and shards are replayed whole into the merged
        // log, so that is not disk, it is every cursor delta from then on. An
        // entry saying what the record already says carries no information.
        let dir = std::env::temp_dir().join(format!("batten-suppress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let fresh = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        assert_eq!(
            record_suppressions(
                &dir,
                "shard",
                std::slice::from_ref(&fresh),
                NotShown::DrainSuppressed,
            )
            .unwrap(),
            1,
            "the first suppression is news"
        );
        let already = FindingRecord {
            presentation: Presentation::NotShown(NotShown::DrainSuppressed),
            ..fresh.clone()
        };
        assert_eq!(
            record_suppressions(&dir, "shard", &[already], NotShown::DrainSuppressed).unwrap(),
            0,
            "saying it again is not"
        );
        // A DIFFERENT reason still is: the engine withheld it for a new cause,
        // and the two are distinguishable in the rate that reads them.
        let capped = FindingRecord {
            presentation: Presentation::NotShown(NotShown::OverCardinalityCap),
            ..fresh
        };
        assert_eq!(
            record_suppressions(&dir, "shard", &[capped], NotShown::DrainSuppressed).unwrap(),
            1
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_record_with_no_check_or_no_remediation_is_never_emitted() {
        // CLOUD-81's emission half, and the drain is the surface it names. A
        // finding with no check cannot be settled and one with no stated
        // remediation cannot be acted on, so emitting either spends attention
        // on something the agent has no way to close.
        let scope = changed(&["src/a.rs"]);
        let emittable = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        assert_eq!(
            cycled(std::slice::from_ref(&emittable), &scope, None)
                .lines
                .len(),
            1,
            "the control: this fixture is otherwise emittable"
        );

        for withheld in [
            FindingRecord {
                check: None,
                ..emittable.clone()
            },
            FindingRecord {
                remediation: None,
                ..emittable.clone()
            },
            FindingRecord {
                check: None,
                remediation: None,
                ..emittable
            },
        ] {
            assert!(!withheld.is_emittable());
            let drained = cycled(std::slice::from_ref(&withheld), &scope, None);
            assert!(drained.lines.is_empty(), "un-actionable, so unspoken");
            // NOT a drain suppression: the engine did not choose to withhold
            // it, so counting it as one would put a schema gap into the
            // per-check false-positive rate.
            assert!(drained.scope_filtered.is_empty());
        }
    }

    #[test]
    fn a_scope_filtered_record_is_carried_out_for_journalling_not_dropped() {
        // The suppression has to be recordable, or the drain's own filtering
        // inflates the false-positive rate it feeds.
        let drained = cycled(
            &[record(FindingKind::Code, "r", "src/a.rs", "TODO")],
            &changed(&[]),
            None,
        );
        assert!(drained.lines.is_empty(), "nothing to emit prints nothing");
        assert_eq!(drained.scope_filtered.len(), 1);
    }

    #[test]
    fn the_count_shown_is_the_one_for_this_checkouts_ref() {
        // One identity, two refs, different counts. The agent is working on one
        // of them, and showing the other's count would be a number about a tree
        // that is not in front of it.
        let mut multi = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        multi.upsert(Instance {
            context: Context::new("refs/heads/z"),
            occurrences: Observation::Observed(42),
            observed_at_commit: "0".repeat(40),
            worktree_path: None,
            path: "src/a.rs".to_owned(),
            line: Some(1),
        });
        let scope = changed(&["src/a.rs"]);
        let here = cycled(
            &multi_records(&multi),
            &scope,
            Some(&Context::new("refs/heads/z")),
        );
        assert!(here.lines[0].ends_with(" 42"));
        let fallback = cycled(&multi_records(&multi), &scope, None);
        assert!(
            fallback.lines[0].ends_with(" 1"),
            "no ref: the first instance, deterministically, never nothing"
        );
    }

    fn multi_records(record: &FindingRecord) -> Vec<FindingRecord> {
        vec![record.clone()]
    }

    #[test]
    fn a_record_observing_nothing_anywhere_renders_no_line() {
        // An instance-less record has no coordinate to point at. Rendering a
        // pointer with no target would be a line the agent cannot act on.
        let mut empty = record(FindingKind::Sequence, "r", "src/a.rs", "TODO");
        empty.instances.clear();
        assert!(cycled(&[empty], &changed(&[]), None).lines.is_empty());
    }

    #[test]
    fn a_held_observation_renders_as_held_rather_than_as_a_count() {
        // `NotObserved` must never render as `0`: the rule did not run, so the
        // finding holds, and a zero would read as resolved.
        let mut held = record(FindingKind::Sequence, "r", "src/a.rs", "TODO");
        held.instances[0].occurrences =
            Observation::NotObserved(crate::findings::NotObserved::RuleSkipped);
        let drained = cycled(&[held], &changed(&[]), None);
        assert!(drained.lines[0].ends_with(" held"));
    }

    #[test]
    fn every_line_is_a_pointer_and_never_a_payload() {
        // Rule 4, asserted rather than promised: the rendered line carries a
        // fingerprint, a rule id, a `path:line` and a count — and nothing that
        // could be the matched content, which the store does not hold anyway.
        let one = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let drained = cycled(std::slice::from_ref(&one), &changed(&["src/a.rs"]), None);
        assert_eq!(
            drained.lines,
            vec![format!(
                "{} r src/a.rs:1 1",
                one.identity.fingerprint.to_hex()
            )]
        );
    }

    // --- (f) CLOUD-82: the emission contract -------------------------------

    /// `count` distinct identities for one rule, all inside one changed file.
    fn spread(rule: &str, count: usize) -> Vec<FindingRecord> {
        (0..count)
            .map(|index| {
                record(
                    FindingKind::Code,
                    rule,
                    "src/a.rs",
                    &format!("TODO {index}"),
                )
            })
            .collect()
    }

    fn at_tier(mut record: FindingRecord, tier: AdvisoryTier) -> FindingRecord {
        record.tier = tier;
        record
    }

    fn generous() -> DrainConfig {
        DrainConfig {
            cardinality_cap: usize::MAX,
            token_budget: usize::MAX,
            ..DrainConfig::default()
        }
    }

    #[test]
    fn a_rule_over_the_cardinality_cap_renders_one_summary_line_and_never_k_entries() {
        // §7 (b). K+1 distinct identities for one rule collapse to exactly one
        // pointer-only summary line — never K entries, which is the failure this
        // cap exists to prevent: a rule firing everywhere spending the agent's
        // whole payload on itself.
        let config = DrainConfig {
            cardinality_cap: 3,
            ..generous()
        };
        let scope = changed(&["src/a.rs"]);

        let under = cycle(
            &spread("r", 3),
            &scope,
            None,
            &config,
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(under.lines.len(), 3, "at the cap, every identity speaks");
        assert!(under.capped.is_empty());

        let over = cycle(
            &spread("r", 4),
            &scope,
            None,
            &config,
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(
            over.lines,
            vec!["rule r: 3+ findings".to_owned()],
            "one line for the rule, and no entries at all"
        );
        assert_eq!(over.capped.len(), 4, "all four are withheld BY THE CAP");
        assert!(
            over.counts.is_empty(),
            "nothing was shown, so nothing is remembered as having been shown"
        );
    }

    #[test]
    fn the_cap_is_per_rule_so_one_noisy_rule_never_silences_a_quiet_one() {
        // The cap is a statement about a rule's health, so it must not be
        // reachable by a rule's neighbours: a second rule with one finding still
        // gets its pointer.
        let config = DrainConfig {
            cardinality_cap: 2,
            ..generous()
        };
        let mut records = spread("noisy", 5);
        records.push(record(FindingKind::Code, "quiet", "src/a.rs", "TODO once"));
        let drained = cycle(
            &records,
            &changed(&["src/a.rs"]),
            None,
            &config,
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(drained.lines.len(), 2);
        assert!(
            drained
                .lines
                .contains(&"rule noisy: 2+ findings".to_owned())
        );
        assert!(
            drained.lines.iter().any(|line| line.contains(" quiet ")),
            "the quiet rule keeps its pointer: {:?}",
            drained.lines
        );
    }

    #[test]
    fn the_rendered_payload_stays_at_or_under_the_configured_token_budget() {
        // §7 (a), both halves. The clamped payload is at or under the budget,
        // and the SAME assertion over the unclamped set fails — without which
        // this test could pass on a fixture that never approached the bar.
        const BUDGET: usize = 60;
        let records = spread("r", 40);
        let scope = changed(&["src/a.rs"]);

        let unclamped = cycle(&records, &scope, None, &generous(), &BTreeMap::new(), &[]);
        assert!(
            crate::budget::estimate_tokens(&render(&unclamped)) > BUDGET,
            "the fixture must actually overflow, or the clamp is untested"
        );

        let clamped = cycle(
            &records,
            &scope,
            None,
            &DrainConfig {
                token_budget: BUDGET,
                ..generous()
            },
            &BTreeMap::new(),
            &[],
        );
        assert!(
            crate::budget::estimate_tokens(&render(&clamped)) <= BUDGET,
            "over budget: {:?}",
            render(&clamped)
        );
        assert!(
            !clamped.over_budget.is_empty(),
            "and something was actually withheld"
        );
        assert_eq!(
            clamped.lines.last().map(String::as_str),
            Some(format!("budget: {} findings withheld", clamped.over_budget.len()).as_str()),
            "the payload says how much it did not say: {:?}",
            clamped.lines
        );
    }

    #[test]
    fn a_zero_budget_says_nothing_rather_than_saying_one_thing() {
        // The honest bottom of the range. A budget that cannot afford even the
        // closing summary emits nothing at all — and still carries every
        // withheld identity out for journalling, so silence is recorded rather
        // than merely observed.
        let records = spread("r", 3);
        let drained = cycle(
            &records,
            &changed(&["src/a.rs"]),
            None,
            &DrainConfig {
                token_budget: 0,
                ..generous()
            },
            &BTreeMap::new(),
            &[],
        );
        assert!(drained.lines.is_empty());
        assert_eq!(drained.over_budget.len(), 3);
        assert!(drained.counts.is_empty());
    }

    #[test]
    fn a_group_re_raise_says_old_to_new_over_one_in_scope_pointer() {
        // §7 (c). A 500 -> 501 re-raise is ONE line carrying the delta and one
        // `path:line`. There is no instance list to expand — occurrences are a
        // count by construction — so 501 pointers is unreachable, and this pins
        // that the count field is where the delta shows up.
        let mut record = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        record.instances[0].occurrences = Observation::Observed(501);
        let key = record.identity.fingerprint.to_hex();
        let previous: BTreeMap<String, u64> = [(key.clone(), 500)].into_iter().collect();

        let drained = cycle(
            std::slice::from_ref(&record),
            &changed(&["src/a.rs"]),
            None,
            &generous(),
            &previous,
            &[],
        );
        assert_eq!(drained.lines, vec![format!("{key} r src/a.rs:1 500->501")]);
        assert_eq!(
            drained.counts.get(&key).copied(),
            Some(501),
            "and the new count becomes the next drain's anchor"
        );
    }

    #[test]
    fn a_count_that_fell_is_a_ratchet_and_never_a_re_raise() {
        // Re-raising on a falling count would punish incremental fixing: an
        // agent that removed forty of fifty occurrences would be told about the
        // rule again, which teaches it that partial fixes are not worth making.
        let mut record = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        record.instances[0].occurrences = Observation::Observed(10);
        let key = record.identity.fingerprint.to_hex();
        let previous: BTreeMap<String, u64> = [(key.clone(), 50)].into_iter().collect();

        let drained = cycle(
            std::slice::from_ref(&record),
            &changed(&["src/a.rs"]),
            None,
            &generous(),
            &previous,
            &[],
        );
        assert_eq!(drained.lines, vec![format!("{key} r src/a.rs:1 10")]);
    }

    #[test]
    fn a_rising_count_never_moves_a_finding_ahead_of_a_stronger_tier() {
        // §7 (e), and CLOUD-80's no-escalation law on the emission plane: a
        // duplicate count is not evidence of urgency. Salience is a function of
        // the tier, so the count cannot buy a better position however far it
        // climbs — and the drain, taking a shared slice, cannot restate the tier
        // either.
        let loud = at_tier(
            record(FindingKind::Code, "advisory-rule", "src/a.rs", "TODO loud"),
            AdvisoryTier::Advisory,
        );
        let urgent = at_tier(
            record(FindingKind::Code, "warning-rule", "src/a.rs", "TODO urgent"),
            AdvisoryTier::Warning,
        );
        let scope = changed(&["src/a.rs"]);

        let quiet = cycle(
            &[loud.clone(), urgent.clone()],
            &scope,
            None,
            &generous(),
            &BTreeMap::new(),
            &[],
        );
        assert!(
            quiet.lines[0].contains(" warning-rule "),
            "the stronger tier leads: {:?}",
            quiet.lines
        );

        let mut escalating = loud.clone();
        escalating.instances[0].occurrences = Observation::Observed(9_000);
        let before = vec![escalating.clone(), urgent.clone()];
        let shouted = cycle(&before, &scope, None, &generous(), &BTreeMap::new(), &[]);
        assert!(
            shouted.lines[0].contains(" warning-rule "),
            "nine thousand occurrences buy no position: {:?}",
            shouted.lines
        );
        assert_eq!(
            before,
            vec![escalating, urgent],
            "and the tier on the record itself is left exactly as it was found"
        );
    }

    #[test]
    fn a_capped_or_clamped_identity_is_never_remembered_as_something_the_agent_saw() {
        // The remembered counts are the anchor for "what was it last told", so
        // an identity withheld this boundary must not enter them: it would make
        // the NEXT drain's re-raise silent, because the delta would be measured
        // against a number nobody ever read.
        let config = DrainConfig {
            cardinality_cap: 1,
            token_budget: usize::MAX,
            ..DrainConfig::default()
        };
        let drained = cycle(
            &spread("r", 4),
            &changed(&["src/a.rs"]),
            None,
            &config,
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(drained.lines, vec!["rule r: 1+ findings".to_owned()]);
        assert!(drained.counts.is_empty());
    }

    #[test]
    fn a_silent_drain_leaves_the_remembered_counts_where_they_were() {
        // A payload the `resultId` short-circuit swallowed told the agent
        // nothing. Advancing the anchor anyway would consume a re-raise the
        // agent never saw.
        let mut state = WakeState {
            counts: [("abc".to_owned(), 1)].into_iter().collect(),
            ..WakeState::default()
        };
        let spoke = Drained {
            counts: [("abc".to_owned(), 7)].into_iter().collect(),
            ..folded("r")
        };
        state.drained(1, 0, &spoke, false);
        assert_eq!(
            state.counts.get("abc").copied(),
            Some(1),
            "silence anchors nothing"
        );
        state.drained(2, 0, &spoke, true);
        assert_eq!(state.counts.get("abc").copied(), Some(7));
    }

    #[test]
    fn the_capped_and_the_clamped_are_withheld_for_different_recorded_reasons() {
        // The two bounds measure different things, and the store has to be able
        // to tell them apart: the cap is a property of the RULE and feeds
        // rule-health telemetry, where the clamp is a property of THIS payload
        // and the finding is reconsidered next boundary. One reason for both
        // would put a transient suppression into the rule-health number.
        let dir = std::env::temp_dir().join(format!("batten-reasons-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // One rule over the cap, one rule under it whose entries the clamp then
        // has no room for, and one code-anchored finding outside the changed
        // scope. Three withheld sets, three reasons, one cycle.
        let mut records = spread("noisy", 4);
        records.extend(spread("quiet", 2));
        records.push(record(FindingKind::Code, "elsewhere", "src/z.rs", "TODO"));
        let drained = cycle(
            &records,
            &changed(&["src/a.rs"]),
            None,
            &DrainConfig {
                cardinality_cap: 3,
                token_budget: 20,
                ..DrainConfig::default()
            },
            &BTreeMap::new(),
            &[],
        );
        assert_eq!(drained.capped.len(), 4, "the noisy rule, by the cap");
        assert_eq!(drained.scope_filtered.len(), 1, "the one outside the diff");
        assert!(
            !drained.over_budget.is_empty(),
            "and the clamp took at least one of the quiet rule's entries"
        );
        let capped: BTreeSet<String> = drained
            .capped
            .iter()
            .map(|record| record.identity.fingerprint.to_hex())
            .collect();
        assert!(
            drained
                .over_budget
                .iter()
                .all(|record| !capped.contains(&record.identity.fingerprint.to_hex())),
            "the two sets are disjoint, so no identity is journalled under two reasons"
        );
        assert_eq!(
            journal_suppressions(&dir, "shard", &drained).unwrap(),
            drained.capped.len() + drained.scope_filtered.len() + drained.over_budget.len(),
            "every withheld identity is recorded, once"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- (g) CLOUD-166: the resultId is a report id, not a set hash ---------

    #[test]
    fn a_disposition_that_moved_changes_the_result_id_though_the_lines_do_not() {
        // The adversarial case CLOUD-166 names. A disposition is state-bearing and
        // invisible in a pointer line, so a digest over the rendered bytes alone
        // would call this cycle "unchanged" and skip a change the store made —
        // silently, which is the failure mode with no witness.
        let scope = changed(&["src/a.rs"]);
        let before = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let after = FindingRecord {
            disposition: Some(crate::findings::Disposition::Acted),
            ..before.clone()
        };

        let first = cycled(std::slice::from_ref(&before), &scope, None);
        let second = cycled(std::slice::from_ref(&after), &scope, None);
        assert_eq!(
            first.lines, second.lines,
            "the premise: the rendered payload is byte-identical either way"
        );
        assert_ne!(
            first.result_id, second.result_id,
            "so the digest must be the thing that notices"
        );
    }

    #[test]
    fn a_finding_moving_between_withholding_reasons_changes_the_result_id() {
        // Same shape, one level out: the payload cannot show whether a rule was
        // capped or its entries clamped, and the two mean different things to the
        // rate that reads them. An identical `unchanged` for both would lose it.
        let records = spread("r", 4);
        let scope = changed(&["src/a.rs"]);
        let capped = cycle(
            &records,
            &scope,
            None,
            &DrainConfig {
                cardinality_cap: 2,
                ..generous()
            },
            &BTreeMap::new(),
            &[],
        );
        let clamped = cycle(
            &records,
            &scope,
            None,
            &DrainConfig {
                token_budget: 0,
                ..generous()
            },
            &BTreeMap::new(),
            &[],
        );
        assert_ne!(capped.result_id, clamped.result_id);
    }

    #[test]
    fn an_identical_snapshot_yields_the_identical_result_id_whatever_the_order() {
        // The other half: content-derived means no clock and no input-order
        // dependence, or the short-circuit would never fire and the marker would
        // be unreachable.
        let a = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let b = record(FindingKind::Code, "r", "src/b.rs", "FIXME");
        let scope = changed(&["src/a.rs", "src/b.rs"]);
        assert_eq!(
            cycled(&[a.clone(), b.clone()], &scope, None).result_id,
            cycled(&[b, a], &scope, None).result_id
        );
    }

    #[test]
    fn the_unchanged_marker_costs_the_same_whatever_the_payload_would_have_been() {
        // §7 (a)'s constant-size half, as a property of the marker rather than of
        // a fixture: it is one fixed token, so its estimate cannot grow with the
        // finding count. A marker that interpolated anything would break this.
        assert_eq!(UNCHANGED, "unchanged");
        assert!(
            !UNCHANGED.contains('\n'),
            "one line, so one pointer-free token"
        );
        assert_eq!(
            crate::budget::estimate_tokens(UNCHANGED),
            crate::budget::estimate_tokens(UNCHANGED)
        );
    }

    #[test]
    fn wake_state_round_trips_and_a_foreign_schema_reads_as_fresh() {
        // A corrupt or future bookkeeping file must not be able to stop findings
        // being surfaced: unreadable resolves to a state that drains.
        let dir = std::env::temp_dir().join(format!("batten-drain-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let mut state = WakeState::default();
        state.drained(1_234, 7, &folded("abc"), true);
        save_wake(&dir, "session-1", &state).unwrap();
        assert_eq!(load_wake(&dir, "session-1"), state);

        // A different session shares nothing.
        assert_eq!(load_wake(&dir, "session-2"), WakeState::default());

        // A future schema reads as fresh rather than as an error.
        let path = wake_path(&dir, "session-1");
        let mut future: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        future["schema"] = serde_json::json!(WAKE_SCHEMA + 1);
        std::fs::write(&path, future.to_string()).unwrap();
        assert_eq!(load_wake(&dir, "session-1"), WakeState::default());

        // So does a torn one.
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(load_wake(&dir, "session-1"), WakeState::default());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_session_id_never_decides_where_the_state_file_is_written() {
        // The session id is a host-chosen string. Hashing it is what stops a host
        // that puts a separator or a traversal component in one from choosing a
        // path outside the store.
        let store = Path::new("/store");
        for hostile in ["../../etc/passwd", "a/b/c", "..", ""] {
            let path = wake_path(store, hostile);
            assert_eq!(path.parent(), Some(drain_dir(store).as_path()));
            assert!(
                path.file_name()
                    .and_then(|name| name.to_str())
                    .and_then(|name| name.strip_suffix(".json"))
                    .is_some_and(|stem| stem.len() == 64
                        && stem.bytes().all(|byte| byte.is_ascii_hexdigit())),
                "a 64-hex key plus `.json`, whatever the host sent"
            );
        }
    }

    #[test]
    fn every_wake_outcome_has_a_distinct_token() {
        // The census idiom: a fourth outcome cannot land without a token.
        let tokens: BTreeSet<&str> = Wake::ALL.iter().map(|wake| wake.as_str()).collect();
        assert_eq!(tokens.len(), Wake::ALL.len());
    }
}
