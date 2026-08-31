//! The guard-decision telemetry record (CLOUD-133): what a gate or hook decision
//! emits, and where it is stored.
//!
//! CLOUD-32 landed the `config_epoch` **value** and explicitly descoped stamping
//! it, for a reason stronger than sequencing: there was nothing to stamp it onto.
//! [`crate::hook`] adjudicates and emits no record, [`crate::receipt`] records a
//! verification claim rather than a decision, and [`crate::findings`] holds
//! findings rather than decisions. This is that record — the schema its consumers
//! (an external security layer reading these logs, offline rule synthesis, and
//! deterministic false-positive rule tuning) all read.
//!
//! # Two planes, and this is the observability one
//!
//! A gate's *verdict* is a computable predicate, never a model judgement
//! (CLOUD-93 / CLOUD-131). Recording **who called** — which model, through which
//! harness, in which session — is provenance, not judgement. Nothing here
//! participates in any verdict; the record is written after one is reached.
//!
//! # Rule 4 is structural here, not editorial
//!
//! A record over guard decisions is the richest source of sensitive content the
//! engine could hold: the mediated command, the tool input, the surrounding
//! agent context. So the defence is not "remember to hash it" —
//! **no constructor in this module accepts bytes or free text.** [`Subject`] is a
//! [`StoredIdentity`] and [`ContextPointer`] is a [`Fingerprint`] plus a count,
//! both minted by [`crate::identity`] before they reach this module. A caller
//! cannot leak by accident, only by adding a field that does not exist. That is
//! [`crate::judge`]'s posture (`PayloadEntry::text` is the only bytes-bearing
//! field) taken one step further: here there is no such field at all.
//!
//! # The subject IS the finding identity
//!
//! Where the mediated subject corresponds to a finding, its pointer is the
//! finding-identity fingerprint (CLOUD-123) — never a second, divergent hash of
//! the same bytes — with the per-kind `identity_version` beside it, because a
//! version bump without the version field would silently break the join to
//! CLOUD-78's dispositions across the transition window. Where **no** finding
//! identity corresponds, the record says [`Subject::Unattributed`] rather than
//! minting one, which is a real answer and not a placeholder: inventing a hash
//! is the exact thing the join rule forbids.
//!
//! # Byte-stability with a clock in the record
//!
//! §6 requires the same input to render the same bytes, and a record carries a
//! timestamp. Both hold because the timestamp is an **input**: [`RecordedAt`] is
//! threaded in as data and [`RecordedAt::now`] is the one clock read, the way
//! [`crate::waiver::today`] stands in front of every waiver predicate. Same
//! inputs, same bytes — including the clock reading.
//!
//! # Append-only, and one definition of it
//!
//! Records are JSON Lines under the repository's out-of-tree state directory
//! ([`crate::state::repo_state_dir`], the root [`crate::capture`] and the epoch
//! cache already use), one shard per writer so the concurrent path shares no
//! mutable file and needs no lock — [`crate::journal`]'s design, reusing its
//! [`crate::journal::shard_id`] rather than growing a second answer to "which
//! shard is this writer's". [`append`] fsyncs before returning: persist before
//! emit.
//!
//! The append-only *predicate* is a **byte prefix**, not a growing id set, and
//! it is [`crate::defects::first_divergence`] — CLOUD-52's, reused rather than
//! re-typed, so the tree has one definition of "append-only". A prefix also
//! freezes past rows' bytes, which is what catches the quiet rewrite an id-set
//! check waves through.
//!
//! # What v1 deliberately is not
//!
//! Capturing the context as an **embedding/vector** is out of scope and filed as
//! CLOUD-134: it needs an embedding source and a leakage review of what the
//! vector encodes. v1 records a pointer and a byte count.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::identity::{Fingerprint, StoredIdentity};
use crate::{journal, state};

/// The record's own schema version, versioned independently of the findings
/// store's ([`crate::findings::FINDINGS_SCHEMA`]) — the two move for unrelated
/// reasons, and [`crate::journal::Format`] already sets that precedent.
pub const DECISION_SCHEMA: u32 = 1;

/// The directory decision records live in, under the repository's state root.
const DECISIONS_DIR: &str = "decisions";

/// The token a provenance field carries when the host declared nothing.
///
/// Named rather than spelled at each site, because CLOUD-275 keys on it: a
/// consumer asking "which model touched this commit" must be able to tell a
/// degraded answer from a missing field.
pub const UNKNOWN: &str = "unknown";

/// One caller-provenance value: what the host declared, or that it declared
/// nothing.
///
/// The fields are **present on every record** and degrade in their *value*, not
/// by disappearing (CLOUD-275): a consumer must be able to distinguish "this
/// host exposes no model identity" from "this record predates the field".
///
/// [`Provenance::from_host`] normalizes empty and whitespace-only to
/// [`Provenance::Unknown`], the same degradation [`crate::hook::Envelope`]'s
/// `session` performs — absent and empty are the same claim from a host that
/// set a variable it could not fill.
///
/// **Stated limit:** a host that literally declares the string `unknown` is
/// indistinguishable from a degraded one. That under-attributes, which is the
/// safe direction, and the alternative — a sentinel no host could ever emit —
/// buys a distinction no consumer has asked for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provenance {
    /// The host declared this value.
    Declared(String),
    /// The host exposes no such identity.
    Unknown,
}

impl Provenance {
    /// What a host reported, degraded to [`Provenance::Unknown`] when it
    /// reported nothing usable.
    #[must_use]
    pub fn from_host(declared: Option<&str>) -> Self {
        match declared.map(str::trim) {
            Some(value) if !value.is_empty() => Provenance::Declared(value.to_owned()),
            _ => Provenance::Unknown,
        }
    }

    /// The stable token this value is recorded as.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Provenance::Declared(value) => value,
            Provenance::Unknown => UNKNOWN,
        }
    }
}

impl Serialize for Provenance {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Provenance {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = String::deserialize(deserializer)?;
        Ok(if token == UNKNOWN {
            Provenance::Unknown
        } else {
            Provenance::Declared(token)
        })
    }
}

/// Who made the mediated call: which model, through which harness, in which
/// session.
///
/// A hook caller passes [`crate::hook::Harness::as_str`] for `harness`. This
/// module imports nothing from [`crate::hook`] on purpose — a decision can also
/// come from a gate no harness invoked, where the honest answer is
/// [`Provenance::Unknown`] rather than a harness token invented to fill a field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Caller {
    /// The model that made the call, as the host names it.
    pub model_id: Provenance,
    /// The harness or agent the call came through.
    pub harness: Provenance,
    /// The host's session id.
    pub session: Provenance,
}

impl Caller {
    /// The caller a host that declared nothing produces: three present fields,
    /// three degraded values.
    #[must_use]
    pub const fn undeclared() -> Self {
        Caller {
            model_id: Provenance::Unknown,
            harness: Provenance::Unknown,
            session: Provenance::Unknown,
        }
    }

    /// The caller a host reported, each field degraded independently.
    #[must_use]
    pub fn from_host(model_id: Option<&str>, harness: Option<&str>, session: Option<&str>) -> Self {
        Caller {
            model_id: Provenance::from_host(model_id),
            harness: Provenance::from_host(harness),
            session: Provenance::from_host(session),
        }
    }
}

/// A pointer to the entity or command that was mediated — never the thing itself.
///
/// See the module docs: where a finding identity corresponds, it **is** the
/// pointer (CLOUD-123); where none does, that is recorded as an answer rather
/// than papered over with a hash minted here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Subject {
    /// The mediated subject corresponds to a finding: its stored identity, which
    /// carries the per-kind `identity_version` beside the fingerprint.
    Identified {
        /// The finding identity — the only join key to CLOUD-78's dispositions.
        identity: StoredIdentity,
    },
    /// No finding identity corresponds to this subject.
    Unattributed,
}

impl Subject {
    /// The subject of a decision about a finding.
    #[must_use]
    pub const fn identified(identity: StoredIdentity) -> Self {
        Subject::Identified { identity }
    }
}

/// A pointer to the context a decision was taken in — a digest and a count,
/// never the context.
///
/// The fingerprint comes from [`crate::identity::context_fingerprint`], so this
/// module never sees the bytes it points at. `bytes` is a count, which rule 4
/// permits explicitly and which is what makes an absent context distinguishable
/// from an empty one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum ContextPointer {
    /// The context, as its digest and its size.
    Digest {
        /// The [`crate::identity::context_fingerprint`] of the context bytes.
        fingerprint: Fingerprint,
        /// How many bytes it stood for. Zero is a real answer.
        bytes: u64,
    },
    /// No context was captured for this decision.
    Absent,
}

impl ContextPointer {
    /// Point at context already fingerprinted by [`crate::identity`].
    #[must_use]
    pub const fn digest(fingerprint: Fingerprint, bytes: u64) -> Self {
        ContextPointer::Digest { fingerprint, bytes }
    }
}

/// What the gate decided, in CLOUD-126's vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// The gate ran and found nothing blocking.
    Pass,
    /// The policy verdict: a violation, or a mediated call denied.
    Violation,
    /// The gate did not run — its precondition was unmet, or a capability it
    /// needs is absent on this host.
    Skipped,
    /// The gate could not complete. Fail-closed isolation (CLOUD-126): an
    /// erroring gate is `Internal`, never a silent pass.
    Internal,
}

impl Outcome {
    /// Every outcome, so anything ranging over them is derived rather than typed
    /// twice — [`crate::capture::Stream::ALL`]'s idiom.
    pub const ALL: &'static [Outcome] = &[
        Outcome::Pass,
        Outcome::Violation,
        Outcome::Skipped,
        Outcome::Internal,
    ];

    /// The stable token this outcome is recorded as.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Violation => "violation",
            Outcome::Skipped => "skipped",
            Outcome::Internal => "internal",
        }
    }

    /// The exit code this outcome contributes to the run, branching on named
    /// [`ExitCode`] variants rather than integer literals.
    ///
    /// [`Outcome::Skipped`] contributes **`None`**, not
    /// [`ExitCode::Success`]. A gate that did not run reports nothing, and
    /// reading that silence as a pass is precisely how fail-closed becomes
    /// fail-open — the lesson [`crate::findings::Observation`] encodes for
    /// occurrence counts, applied to verdicts.
    #[must_use]
    pub const fn exit_code(self) -> Option<ExitCode> {
        match self {
            Outcome::Pass => Some(ExitCode::Success),
            Outcome::Violation => Some(ExitCode::Violation),
            Outcome::Skipped => None,
            Outcome::Internal => Some(ExitCode::Internal),
        }
    }

    /// Which of two codes the run reports when both were contributed
    /// (CLOUD-126's one precedence row).
    ///
    /// `Violation` outranks `Internal`, and the reason is what each code tells
    /// the caller to do. `2` means the policy answered and the answer was no —
    /// an instruction unaffected by some other gate having been unevaluable.
    /// `3` means Batten could not answer, which is weaker and less actionable,
    /// and the likeliest reading of `3` in a hook is "retry" — the exact wrong
    /// response to a policy denial. Both are non-zero, so no ordering here can
    /// produce a pass; the choice only decides which non-zero is seen.
    ///
    /// `Usage` is deliberately absent from the ladder rather than ranked below
    /// the others: a malformed invocation never reaches a fold over gate
    /// dispositions, because nothing was evaluated for it to fold.
    const fn outranks(left: ExitCode, right: ExitCode) -> ExitCode {
        match (left, right) {
            (ExitCode::Violation, _) | (_, ExitCode::Violation) => ExitCode::Violation,
            (ExitCode::Internal, _) | (_, ExitCode::Internal) => ExitCode::Internal,
            _ => ExitCode::Success,
        }
    }
}

/// The run's exit code, folded from the dispositions its gates reported
/// (CLOUD-126).
///
/// **A pure function of the disposition multiset**, which is the property
/// CLOUD-126 §2 asks for by name: [`Outcome::outranks`] is commutative and
/// associative, so the answer cannot depend on the order gates were evaluated
/// in. [`tests::the_fold_is_order_independent`] pins that over every permutation
/// of the vocabulary rather than over a hand-picked pair.
///
/// An empty fold is [`ExitCode::Success`], and so is a fold of nothing but
/// [`Outcome::Skipped`] — a run that evaluated no gate found nothing, and the
/// *reporting* of those skips is what keeps that from reading as coverage
/// (CLOUD-125). The exit code is deliberately not where a skip is visible; §5 of
/// that row puts it in output instead, because a skip-only run still exits `0`.
#[must_use]
pub fn fold(outcomes: impl IntoIterator<Item = Outcome>) -> ExitCode {
    outcomes
        .into_iter()
        .filter_map(Outcome::exit_code)
        .fold(ExitCode::Success, Outcome::outranks)
}

/// Where in source control the decision was taken.
///
/// The join key CLOUD-275 answers `sha -> {model, harness, session}` over. The
/// working-state half is a boolean rather than a diff: whether the tree was
/// dirty is what a consumer needs to know about how far the commit describes
/// what was actually mediated, and the diff itself is payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Anchor {
    /// The commit `HEAD` resolved to.
    pub commit: String,
    /// The ref `HEAD` was on, when it was on one. `None` on a detached head —
    /// a real answer, not an empty string.
    pub reference: Option<String>,
    /// Whether the working tree carried uncommitted changes.
    pub dirty: bool,
}

/// When a record was written, as whole seconds since the Unix epoch.
///
/// A newtype rather than a bare integer so the unit cannot be mistaken, and an
/// **input** rather than a clock read at render time: see the module docs on
/// byte-stability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RecordedAt(u64);

impl RecordedAt {
    /// A recording time supplied by the caller.
    #[must_use]
    pub const fn from_unix_seconds(seconds: u64) -> Self {
        RecordedAt(seconds)
    }

    /// The seconds this stands for.
    #[must_use]
    pub const fn unix_seconds(self) -> u64 {
        self.0
    }

    /// The one clock read in this module, at the boundary rather than in
    /// anything that renders bytes — [`crate::waiver::today`]'s idiom.
    ///
    /// A clock before the Unix epoch yields `0` rather than an error: unlike a
    /// waiver's expiry, nothing here *decides* on the value, so a nonsense clock
    /// costs a misdated record and must not cost the record itself.
    #[must_use]
    pub fn now() -> Self {
        RecordedAt(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
        )
    }
}

/// One guard-decision telemetry event.
///
/// Every field is a pointer, a token, a count or a boolean. See the module docs
/// for why that is a property of the type rather than of its callers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionRecord {
    /// The record schema this line is written in ([`DECISION_SCHEMA`]).
    pub schema: u32,
    /// The CLOUD-32 hash of the config surface that governed this decision — the
    /// attribution join key, present on every record.
    pub config_epoch: String,
    /// The repository, derived at runtime by [`crate::state::derive_repo_name`]
    /// so no repository identifier is baked into the core (rule 1).
    pub repo: String,
    /// Where in source control the decision was taken.
    pub anchor: Anchor,
    /// When it was recorded.
    pub recorded_at: RecordedAt,
    /// Which gate decided.
    pub gate_id: String,
    /// The version of the rule that gate applied, so a record stays readable
    /// across a rule change.
    pub rule_version: String,
    /// What it decided.
    pub outcome: Outcome,
    /// A pointer to what was mediated.
    pub subject: Subject,
    /// A pointer to the context it was mediated in.
    pub context: ContextPointer,
    /// Who made the call.
    pub caller: Caller,
}

impl DecisionRecord {
    /// The single JSON Lines record, without its terminating newline.
    ///
    /// Byte-stable: struct field order is the declaration order above, and every
    /// field is a scalar or a tagged enum, so there is no map whose iteration
    /// order could vary between runs.
    ///
    /// # Errors
    ///
    /// Returns an error only if serialization fails, which for this shape means
    /// an internal failure rather than bad input.
    pub fn to_line(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// The directory decision records live in, under the repository's state root.
fn decisions_dir(repo_root: &Path) -> Result<PathBuf> {
    Ok(state::repo_state_dir(repo_root)?.join(DECISIONS_DIR))
}

/// Append `record` to this worktree's shard, fsynced before returning.
///
/// One shard per writer, keyed by worktree through [`journal::shard_id`], so
/// concurrent sessions never share a mutable file and no lock is needed on the
/// write path. Opened `create` + `append` and never truncating: the append-only
/// property is enforced by how the file is opened, and *checked* by
/// [`verify_append_only`].
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved, or the shard cannot
/// be created, written or synced. Never a silent skip — a decision record that
/// quietly did not happen is indistinguishable from a decision nobody took.
pub fn append(repo_root: &Path, worktree: &Path, record: &DecisionRecord) -> Result<()> {
    let dir = decisions_dir(repo_root)?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create the decision log {}", dir.display()))?;
    let path = dir.join(format!("{}.jsonl", journal::shard_id(worktree)));
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("open the decision shard {}", path.display()))?;
    writeln!(file, "{}", record.to_line()?)
        .with_context(|| format!("append to the decision shard {}", path.display()))?;
    // Persist before emit: a record a consumer has been shown is already on disk.
    file.sync_all()
        .with_context(|| format!("sync the decision shard {}", path.display()))?;
    Ok(())
}

/// Every record in the log, shards read in sorted path order.
///
/// A line that does not parse is dropped rather than failing the read — the torn
/// trailing line of a shard whose writer died mid-append. [`crate::journal`]
/// takes the same position for the same reason: refusing to read every other
/// shard over one partial write makes a crash contagious.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved or a shard cannot be
/// read. An absent log is an empty one, which is the ordinary first-read case.
pub fn load_all(repo_root: &Path) -> Result<Vec<DecisionRecord>> {
    let dir = decisions_dir(repo_root)?;
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return Ok(Vec::new());
    };
    let mut paths: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    // Sorted so a read is a pure function of the shards' contents, never of
    // `read_dir` order (§6).
    paths.sort();

    let mut all = Vec::new();
    for path in paths {
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("read the decision shard {}", path.display()))?;
        all.extend(
            text.lines()
                .filter_map(|line| serde_json::from_str::<DecisionRecord>(line).ok()),
        );
    }
    Ok(all)
}

/// Whether `previous` survives unchanged as a prefix of `current`.
///
/// `None` means append-only held. `Some(line)` is the 1-based line of the first
/// rewritten row, or of the first row that went missing when the log shrank.
///
/// Delegates to [`crate::defects::first_divergence`] rather than re-deriving the
/// predicate: CLOUD-52 already settled that append-only is a **byte prefix** and
/// not a growing id set, and two definitions of one property is the drift this
/// engine exists to refuse.
#[must_use]
pub fn verify_append_only(previous: &str, current: &str) -> Option<usize> {
    crate::defects::first_divergence(previous, current)
}

/// This worktree's shard file, for a caller that needs to snapshot the log
/// before and after an append.
///
/// # Errors
///
/// Returns an error when the state root cannot be resolved.
pub fn shard_path(repo_root: &Path, worktree: &Path) -> Result<PathBuf> {
    Ok(decisions_dir(repo_root)?.join(format!("{}.jsonl", journal::shard_id(worktree))))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::identity::{FindingKind, SpanNormalization, code_fingerprint};

    fn record() -> DecisionRecord {
        DecisionRecord {
            schema: DECISION_SCHEMA,
            config_epoch: "0".repeat(64),
            repo: "demo".to_owned(),
            anchor: Anchor {
                commit: "1".repeat(40),
                reference: Some("refs/heads/topic".to_owned()),
                dirty: false,
            },
            recorded_at: RecordedAt::from_unix_seconds(1_700_000_000),
            gate_id: "protected-mutation".to_owned(),
            rule_version: "1".to_owned(),
            outcome: Outcome::Violation,
            subject: Subject::identified(StoredIdentity::new(
                FindingKind::Code,
                code_fingerprint("r", "src/a.rs", "span", SpanNormalization::Collapsed).unwrap(),
            )),
            context: ContextPointer::digest(crate::identity::context_fingerprint(b"ctx"), 3),
            caller: Caller::from_host(Some("some-model"), Some("claude-code"), Some("s-1")),
        }
    }

    #[test]
    fn a_host_that_declares_nothing_still_fills_every_field() {
        // CLOUD-275: fields present on every record, values degraded. Empty and
        // whitespace-only are the same claim as absent.
        for declared in [None, Some(""), Some("   ")] {
            assert_eq!(Provenance::from_host(declared), Provenance::Unknown);
            assert_eq!(Provenance::from_host(declared).as_str(), UNKNOWN);
        }
        assert_eq!(
            Provenance::from_host(Some(" gpt-x ")),
            Provenance::Declared("gpt-x".to_owned())
        );
        let caller = Caller::undeclared();
        assert_eq!(caller.model_id.as_str(), UNKNOWN);
        assert_eq!(caller.harness.as_str(), UNKNOWN);
        assert_eq!(caller.session.as_str(), UNKNOWN);
    }

    #[test]
    fn every_outcome_has_a_distinct_token() {
        for outcome in Outcome::ALL {
            let token = outcome.as_str();
            assert!(!token.is_empty());
            assert_eq!(
                Outcome::ALL
                    .iter()
                    .filter(|other| other.as_str() == token)
                    .count(),
                1,
                "{token} is declared twice"
            );
        }
    }

    #[test]
    fn violation_is_the_only_outcome_that_reaches_the_deny_code() {
        // The mirror of `exit.rs`'s law that no failure code equals the deny
        // code: read from this side, no outcome other than a policy verdict may
        // be reported as one.
        for outcome in Outcome::ALL {
            let is_deny = outcome.exit_code() == Some(ExitCode::Violation);
            assert_eq!(
                is_deny,
                *outcome == Outcome::Violation,
                "{} maps to the deny code",
                outcome.as_str()
            );
        }
    }

    #[test]
    fn a_skipped_gate_contributes_no_verdict_rather_than_a_pass() {
        // Reading a skipped gate's silence as exit 0 is how fail-closed becomes
        // fail-open — `findings::Observation`'s lesson, at the verdict layer.
        assert_eq!(Outcome::Skipped.exit_code(), None);
        assert_ne!(Outcome::Skipped.exit_code(), Some(ExitCode::Success));
    }

    #[test]
    fn the_fold_reports_a_violation_over_an_error() {
        // CLOUD-126's one precedence row, and the whole reason it is decided
        // rather than deferred: a `3` beside a real violation would downgrade a
        // decided refusal into an infrastructure complaint.
        assert_eq!(
            fold([Outcome::Internal, Outcome::Violation]),
            ExitCode::Violation
        );
        assert_eq!(fold([Outcome::Internal, Outcome::Pass]), ExitCode::Internal);
        assert_eq!(fold([Outcome::Pass, Outcome::Skipped]), ExitCode::Success);
    }

    #[test]
    fn an_empty_or_skip_only_fold_is_success() {
        // A skip contributes nothing, so a run whose every gate skipped exits 0.
        // What keeps that from reading as coverage is the REPORTING of the skips
        // (CLOUD-125 §5), never the exit code — which is why this is the correct
        // answer here rather than a hole.
        assert_eq!(fold([]), ExitCode::Success);
        assert_eq!(
            fold([Outcome::Skipped, Outcome::Skipped]),
            ExitCode::Success
        );
    }

    #[test]
    fn no_fold_of_non_pass_outcomes_can_reach_success() {
        // The fail-closed direction, swept rather than sampled: any multiset
        // containing an error or a violation exits non-zero, whatever else is in
        // it. This is the clause "an unevaluable gate never resolves to pass"
        // reduces to once the fold exists.
        for other in Outcome::ALL {
            for blocking in [Outcome::Violation, Outcome::Internal] {
                let code = fold([*other, blocking]);
                assert_ne!(
                    code,
                    ExitCode::Success,
                    "{} beside {} reported a pass",
                    other.as_str(),
                    blocking.as_str()
                );
            }
        }
    }

    #[test]
    fn the_fold_is_order_independent() {
        // CLOUD-126 §2 asks for "a pure function of the disposition multiset …
        // with no reference to evaluation order". Asserted over every ordered
        // pair AND every rotation of the whole vocabulary, because a fold that
        // is commutative on pairs can still be order-sensitive on three.
        for left in Outcome::ALL {
            for right in Outcome::ALL {
                assert_eq!(
                    fold([*left, *right]),
                    fold([*right, *left]),
                    "{} and {} fold differently by order",
                    left.as_str(),
                    right.as_str()
                );
            }
        }
        let all: Vec<Outcome> = Outcome::ALL.to_vec();
        let expected = fold(all.clone());
        for rotation in 0..all.len() {
            let mut rotated = all.clone();
            rotated.rotate_left(rotation);
            assert_eq!(fold(rotated), expected, "rotation {rotation} disagrees");
        }
    }

    #[test]
    fn a_record_round_trips_through_its_line() {
        let original = record();
        let line = original.to_line().unwrap();
        assert_eq!(
            serde_json::from_str::<DecisionRecord>(&line).unwrap(),
            original
        );
    }

    #[test]
    fn an_unknown_provenance_round_trips_as_the_token() {
        let mut original = record();
        original.caller = Caller::undeclared();
        let line = original.to_line().unwrap();
        assert!(line.contains(UNKNOWN));
        assert_eq!(
            serde_json::from_str::<DecisionRecord>(&line).unwrap(),
            original
        );
    }

    #[test]
    fn an_absent_context_is_distinguishable_from_an_empty_one() {
        // Zero bytes is a real answer — "there was context and it was empty" —
        // and must not read as "no context was captured".
        let empty = ContextPointer::digest(crate::identity::context_fingerprint(b""), 0);
        assert_ne!(empty, ContextPointer::Absent);
        let mut absent = record();
        absent.context = ContextPointer::Absent;
        assert_ne!(absent.to_line().unwrap(), record().to_line().unwrap());
    }
}
