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
//! Emission is deliberately thin: one pointer line per surfaced identity. The
//! shape, the per-rule cardinality cap and the token budget are CLOUD-82's
//! contract, and it replaces [`render`] rather than extending it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::findings::{Context, FindingRecord, Instance, NotShown, Observation, Presentation};
use crate::identity::{FindingKind, drain_result_fingerprint};
use crate::journal;

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

/// The `[drain]` table: how often the advisory drain may wake, and when it stops
/// asking.
///
/// Both keys are **pacing**, which is why neither is layered raise-only by
/// [`crate::resolve`]: "raise" has no meaning for an interval — a longer one is
/// quieter and a shorter one is louder, and neither direction is a weakening of
/// a bar. The committed authority sets it, and a local file does not move it.
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
}

fn default_interval_ms() -> u64 {
    DEFAULT_INTERVAL_MS
}

fn default_empty_poll_giveup() -> u32 {
    DEFAULT_EMPTY_POLL_GIVEUP
}

impl Default for DrainConfig {
    fn default() -> Self {
        DrainConfig {
            interval_ms: DEFAULT_INTERVAL_MS,
            empty_poll_giveup: DEFAULT_EMPTY_POLL_GIVEUP,
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
    /// The digest of the last payload rendered, as hex. The `resultId`
    /// short-circuit compares against this.
    #[serde(rename = "resultId", default, skip_serializing_if = "Option::is_none")]
    pub result_id: Option<String>,
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
            result_id: None,
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
    pub fn drained(&mut self, now_ms: u64, seqno: u64, result_id: String, emitted: bool) {
        self.last_drain_ms = now_ms;
        self.pending = false;
        self.armed_seqno = seqno;
        self.result_id = Some(result_id);
        if emitted {
            self.empty_polls = 0;
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

/// One drain cycle's result: what to say, what was withheld, and the digest that
/// decides whether saying it again would be repetition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drained {
    /// The pointer lines to emit, sorted so the payload is byte-stable.
    pub lines: Vec<String>,
    /// Identities the scope filter withheld.
    pub scope_filtered: Vec<FindingRecord>,
    /// Re-raises of an identity already carried by this payload, suppressed and
    /// counted rather than emitted twice.
    pub duplicates: usize,
    /// The digest of [`Drained::lines`], as hex.
    pub result_id: String,
}

/// Render one line for a record, given the instance to point at.
///
/// **Pointer-only** (rule 4): a fingerprint, a rule id, a `path:line` coordinate
/// and a count. The store holds no matched content, so there is none here to
/// leak — the discipline is stated anyway because the renderer is what CLOUD-82
/// replaces, and it inherits the contract rather than re-deriving it.
fn render_line(record: &FindingRecord, instance: &Instance) -> String {
    let count = match instance.occurrences {
        Observation::Observed(count) => count.to_string(),
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
#[must_use]
pub fn cycle(
    records: &[FindingRecord],
    changed: &BTreeSet<String>,
    context: Option<&Context>,
) -> Drained {
    let mut scope_filtered = Vec::new();
    // Keyed by identity, which is what makes "suppressed and counted" the
    // structure rather than a rule applied afterwards: a second record for one
    // identity cannot occupy a second entry.
    let mut shown: BTreeMap<String, String> = BTreeMap::new();
    let mut duplicates = 0;

    for record in records {
        if !in_scope(record, changed) {
            scope_filtered.push(record.clone());
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
        if shown.insert(key, render_line(record, instance)).is_some() {
            duplicates += 1;
        }
    }

    // `BTreeMap` iteration is by fingerprint hex, so the payload is sorted
    // without a sort call and two renders of one snapshot are byte-identical.
    let lines: Vec<String> = shown.into_values().collect();
    let result_id = drain_result_fingerprint(&lines).to_hex();
    Drained {
        lines,
        scope_filtered,
        duplicates,
        result_id,
    }
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
                disposition: None,
                presentation: Presentation::NotShown(why),
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
    use crate::findings::{FINDINGS_SCHEMA, Instance};
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
        };
        let mut state = WakeState::default();
        let start = 1_000_000_u64;

        let mut drains = 0;
        for offset in [0, 5, 11, 40, 130, 700, 1_999] {
            match decide_wake(&state, &config, start + offset, 0) {
                Wake::Drain => {
                    drains += 1;
                    state.drained(start + offset, 0, "r".to_owned(), true);
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
        };
        let mut state = WakeState::default();
        let start = 1_000_000_u64;

        // The drain that opens the window.
        assert_eq!(decide_wake(&state, &config, start, 0), Wake::Drain);
        state.drained(start, 0, "r0".to_owned(), true);

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
        state.drained(start + 1_000, 0, "r1".to_owned(), true);
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
                    empty_poll_giveup: 3
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
                    empty_poll_giveup: 3
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
                    empty_poll_giveup: 3
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
                    empty_poll_giveup: 2
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
                    empty_poll_giveup: 3
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
        state.drained(1, 0, "r".to_owned(), false);
        assert_eq!(state.empty_polls, 3, "silence accumulates");
        state.drained(2, 0, "r".to_owned(), true);
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
        let first = cycle(&records, &scope, None);
        let again = cycle(&records, &scope, None);
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
            cycle(&moved, &scope, None).result_id,
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
            render(&cycle(&[a.clone(), b.clone()], &scope, None)),
            render(&cycle(&[b, a], &scope, None))
        );
    }

    #[test]
    fn a_re_raise_of_one_identity_within_a_drain_is_suppressed_and_counted() {
        // "A re-raise of the same identity within a drain is suppressed and
        // counted" — one line per IDENTITY, never one per record, and the
        // duplicate is a number rather than a silently dropped row.
        let one = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let drained = cycle(
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
    fn a_scope_filtered_record_is_carried_out_for_journalling_not_dropped() {
        // The suppression has to be recordable, or the drain's own filtering
        // inflates the false-positive rate it feeds.
        let drained = cycle(
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
        let here = cycle(
            &multi_records(&multi),
            &scope,
            Some(&Context::new("refs/heads/z")),
        );
        assert!(here.lines[0].ends_with(" 42"));
        let fallback = cycle(&multi_records(&multi), &scope, None);
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
        assert!(cycle(&[empty], &changed(&[]), None).lines.is_empty());
    }

    #[test]
    fn a_held_observation_renders_as_held_rather_than_as_a_count() {
        // `NotObserved` must never render as `0`: the rule did not run, so the
        // finding holds, and a zero would read as resolved.
        let mut held = record(FindingKind::Sequence, "r", "src/a.rs", "TODO");
        held.instances[0].occurrences =
            Observation::NotObserved(crate::findings::NotObserved::RuleSkipped);
        let drained = cycle(&[held], &changed(&[]), None);
        assert!(drained.lines[0].ends_with(" held"));
    }

    #[test]
    fn every_line_is_a_pointer_and_never_a_payload() {
        // Rule 4, asserted rather than promised: the rendered line carries a
        // fingerprint, a rule id, a `path:line` and a count — and nothing that
        // could be the matched content, which the store does not hold anyway.
        let one = record(FindingKind::Code, "r", "src/a.rs", "TODO");
        let drained = cycle(std::slice::from_ref(&one), &changed(&["src/a.rs"]), None);
        assert_eq!(
            drained.lines,
            vec![format!(
                "{} r src/a.rs:1 1",
                one.identity.fingerprint.to_hex()
            )]
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
        state.drained(1_234, 7, "abc".to_owned(), true);
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
