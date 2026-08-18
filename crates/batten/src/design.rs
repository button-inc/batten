//! Design-evidence integrity gates (CLOUD-53): is the *record* behind a
//! decision sound, whatever the decision was?
//!
//! Decision evidence in this project was disciplined by hand, and the one
//! recorded failure shows the hand slipping (CLOUD-76): a closest-analogue claim
//! stood in a spec while its full-text capture had failed, and a person caught
//! the gap rather than a gate. The corpus behind the novel-core claims
//! (CLOUD-210) is largely **absence** claims — "nothing evaluates X
//! client-side" — the class a single counterexample refutes and no capture can
//! attest. A claim recorded `verified` whose polarity is absence is therefore a
//! defect *of the record*, independent of whether the claim happens to be true.
//!
//! # Every gate is an exact comparison over typed fields
//!
//! Non-negotiable rule 3, and it has a sharp consequence worth stating rather
//! than leaving implicit: "the claim asserts an absence" is computable **only**
//! as a declared [`Polarity`] field. Classifying claim *text* as absence-shaped
//! would be a judge, and a judge is advisory-only and structurally unable to
//! block (house style §0.3). So the schema carries the polarity and the gate
//! compares it; no text is classified anywhere in this module, and there is no
//! field whose *content* is read for meaning.
//!
//! # Stdin and nothing else
//!
//! `design audit` reads a JSONL stream of [`Claim`]s on stdin — no
//! consumer-declared workspace path, no filesystem corpus walk, no second source
//! and therefore no precedence question (CLOUD-324). Stdin **subsumes** the path
//! option: a consumer whose corpus is a file in its own repo reaches the gate
//! with `batten design audit < corpus.jsonl`, no credential and no config key,
//! so a path key would buy only the `<` while costing a §8 clause and a
//! filesystem walk inside an otherwise-offline gate. It is also the only shape
//! consumer #1 can dogfood, since rule 7 and `no-docs-tree` forbid an in-repo
//! evidence tree here.
//!
//! That is what keeps this module a **pure function of a string**: no I/O, no
//! clock, no environment. [`crate::run`] reads stdin and hands the text in.
//!
//! # Capture bytes ride inline, and that is what the budget bounds
//!
//! [`Capture::bytes`] carries the captured content itself, which is what makes
//! digest binding computable at all. Rule 4 governs what a check **emits**, not
//! what it reads, and this gate emits no byte of a capture — every [`Problem`]
//! is a line number plus a claim id.
//!
//! A digest with no bytes beside it makes binding **not computable** for that
//! claim, which is never a pass: on a `verified` claim it is an advisory
//! ([`DIGEST_NOT_COMPUTABLE`]), promoted under `--strictness strict`. That is
//! also why [`Capture::byte_count`] is a *declared* field rather than derived —
//! the budget stays checkable for a record whose bytes were not carried, and
//! comparing the declaration against the bytes that *were* carried is itself a
//! gate ([`BYTE_COUNT_MISMATCH`]).
//!
//! # The ladder decides, and this is its first consumer
//!
//! [`crate::config::Strictness`] has resolved since the loader landed and
//! nothing read it. [`blocks`] is where it starts deciding, and it reads **all
//! three ranks** rather than special-casing `Strict`, because each variant's own
//! doc comment already pins its meaning. Promotion runs through
//! [`crate::rules::any_blocking`] — the same machinery `--fail-on-warning` uses
//! — so there is no bespoke `--strict` flag and no second definition of what
//! "advisory" costs.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::config::Strictness;
use crate::error::UsageError;
use crate::identity::{FindingKind, StoredIdentity};
use crate::receipt::hex_sha256;
use crate::rules::Finding;
use crate::severity::RuleSeverity;

/// The pointer a finding names, since the corpus arrives on stdin and has no
/// path. The spelling `config lint --host-rules -` already uses for the same
/// stream, so one convention covers both.
pub const STREAM: &str = "-";

/// The `[design]` table: the one config key this gate reads.
///
/// Deliberately a single key. The corpus is stdin's, the predicates are the
/// engine's, and the only thing a repository gets to say is how large a single
/// capture may be before it is worth a second look.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Design {
    /// The per-capture byte ceiling. Absent means [`DEFAULT_MAX_CAPTURE_BYTES`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_capture_bytes: Option<usize>,
}

/// The engine's per-capture ceiling when a config names none.
///
/// 16 KiB, [`crate::judge::DEFAULT_MAX_PAYLOAD_BYTES`]'s value and for the same
/// reason: large enough for an ordinary page of captured evidence, small enough
/// that a whole-site scrape pasted into one record is noticed.
pub const DEFAULT_MAX_CAPTURE_BYTES: usize = 16_384;

/// The ceiling actually in force, given the authority's value and a local one.
///
/// **Tighten-only**, [`crate::judge::effective_cap`]'s shape: the minimum wins,
/// so a local file may lower the ceiling and one that tries to raise it changes
/// nothing. For a *budget* smaller is stricter, so §8's "may not weaken" reads
/// as "may not raise" here — the direction inverts and is easy to get backwards.
///
/// `[design]` is authority-only today, so nothing local reaches this, which is
/// strictly stronger than tighten-only; the clamp is the semantics waiting for
/// the day a local layer exists.
#[must_use]
pub fn effective_cap(authority: Option<usize>, local: Option<usize>) -> usize {
    let base = authority.unwrap_or(DEFAULT_MAX_CAPTURE_BYTES);
    match local {
        Some(local) => base.min(local),
        None => base,
    }
}

/// Where a claim stands. A closed enum, so an unknown token is a parse error
/// rather than a silent degrade to the weakest variant — which for a record that
/// exists to be audited would mean an unreadable status quietly reading as
/// "nobody claimed anything yet".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Status {
    /// Asserted, with nobody having checked it yet.
    Claimed,
    /// Checked and upheld.
    Verified,
    /// Checked and found false.
    Refuted,
}

impl Status {
    /// Every status, so the census test is total.
    pub const ALL: &'static [Status] = &[Status::Claimed, Status::Verified, Status::Refuted];

    /// The stable lowercase token used in the record and in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Status::Claimed => "claimed",
            Status::Verified => "verified",
            Status::Refuted => "refuted",
        }
    }
}

/// What shape of thing the claim asserts.
///
/// The **declared** field the absence gate compares, and the reason this module
/// classifies no text: an absence claim ("nothing evaluates X") is refuted by a
/// single counterexample and attested by no capture, so recording one as
/// `verified` is a defect of the record. Deciding that from claim prose would be
/// a judge; deciding it from this field is a comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Polarity {
    /// "X exists / X does this" — a capture can attest it.
    Existence,
    /// "Nothing does X" — no capture can attest it.
    Absence,
}

impl Polarity {
    /// Every polarity, so the census test is total.
    pub const ALL: &'static [Polarity] = &[Polarity::Existence, Polarity::Absence];

    /// The stable lowercase token used in the record and in output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Polarity::Existence => "existence",
            Polarity::Absence => "absence",
        }
    }
}

/// The in-toto digest set for a capture; `sha256` is the standard key.
///
/// A struct rather than a bare string, named for what it digests — the
/// convention [`crate::receipt::SubjectDigest`] and
/// [`crate::receipt::PolicyDigest`] already set. A digest set is extensible by
/// design (an algorithm per key), so the record keeps the envelope's shape even
/// while exactly one algorithm is checked.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CaptureDigest {
    /// Lowercase hex SHA-256 over the capture's bytes.
    pub sha256: String,
}

/// The evidence captured for a claim, content-bound by digest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Capture {
    /// What the bytes hash to, as the record declares it.
    pub digest: CaptureDigest,
    /// How many bytes the capture is, as the record **declares** it.
    ///
    /// Declared rather than derived so the budget stays computable for a record
    /// carrying no bytes, and so a declaration disagreeing with the bytes that
    /// *were* carried is itself catchable ([`BYTE_COUNT_MISMATCH`]).
    pub byte_count: usize,
    /// The captured content itself (CLOUD-324: inline, which is what the budget
    /// bounds). Absent makes digest binding **not computable** for this claim —
    /// never a pass, an advisory on a `verified` row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<String>,
}

/// One design-evidence claim — the schema, defined once (CLOUD-324).
///
/// `deny_unknown_fields` with closed enums throughout: an unrecognised key or an
/// unknown token is a parse error, so a corpus written against a newer schema is
/// refused loudly rather than audited against the fields this build happens to
/// understand.
///
/// [`Claim::claimant`] and [`Claim::verifier`] are the dual-identity model, and
/// both are **optional on purpose**. Their absence is precisely what two of the
/// gates decide over, and a required field would turn each of those findings
/// into a parse error — refusing the whole corpus over the one defect class the
/// audit exists to enumerate.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    /// A stable identifier for this claim, unique within the stream.
    pub id: String,
    /// Where the claim stands.
    pub status: Status,
    /// What shape of thing it asserts.
    pub polarity: Polarity,
    /// Where the claim is recorded: a URL, a `path:line`, a sha. **A pointer,
    /// never the claim text** — this record travels, and the audit reports its
    /// id, so there is nothing a body would buy.
    pub source: String,
    /// Who asserted it. Absent is an advisory: a claim nobody signed cannot be
    /// shown not to be self-attested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimant: Option<String>,
    /// Who checked it. Absent is normal on a `claimed` row and a violation on
    /// any other — a status that says somebody checked, with nobody named.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verifier: Option<String>,
    /// The evidence, when there is any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture: Option<Capture>,
}

/// A claim id used by an earlier row.
pub const DUPLICATE_CLAIM_ID: &str = "design-duplicate-claim-id";
/// A `verified` claim whose polarity is `absence` — the defect class CLOUD-210's
/// corpus is built of, and the one no capture could ever discharge.
pub const VERIFIED_ABSENCE: &str = "design-verified-absence";
/// Carried bytes that do not hash to the recorded digest.
pub const DIGEST_MISMATCH: &str = "design-digest-mismatch";
/// A status past `claimed` with no verifier named.
pub const VERIFIER_ABSENT: &str = "design-verifier-absent";
/// Carried bytes whose length disagrees with the declared `byte_count`.
pub const BYTE_COUNT_MISMATCH: &str = "design-byte-count-mismatch";
/// A claim with no claimant recorded.
pub const CLAIMANT_ABSENT: &str = "design-claimant-absent";
/// A `verified` claim whose verifier is its own claimant.
pub const SELF_ATTESTED: &str = "design-self-attested";
/// A `verified` claim carrying no capture bytes, so digest binding cannot be
/// decided either way.
pub const DIGEST_NOT_COMPUTABLE: &str = "design-digest-not-computable";
/// A capture whose declared size is over the configured ceiling.
pub const CAPTURE_OVER_BUDGET: &str = "design-capture-over-budget";

/// Every gate id this module can emit, with its severity.
///
/// The census the repo's totality idiom walks (`defects.rs` set it): a gate that
/// does not appear here, or appears and is never exercised, fails
/// [`tests::every_gate_id_is_reachable`]. That is what keeps the taxonomy from
/// growing a member nothing produces — and what makes "which of these blocks"
/// one table rather than a `match` each caller could get subtly wrong.
pub const GATES: &[(&str, RuleSeverity)] = &[
    (DUPLICATE_CLAIM_ID, RuleSeverity::Deny),
    (VERIFIED_ABSENCE, RuleSeverity::Deny),
    (DIGEST_MISMATCH, RuleSeverity::Deny),
    (VERIFIER_ABSENT, RuleSeverity::Deny),
    (BYTE_COUNT_MISMATCH, RuleSeverity::Deny),
    (CLAIMANT_ABSENT, RuleSeverity::Warn),
    (SELF_ATTESTED, RuleSeverity::Warn),
    (DIGEST_NOT_COMPUTABLE, RuleSeverity::Warn),
    (CAPTURE_OVER_BUDGET, RuleSeverity::Warn),
];

/// The severity a gate id carries.
///
/// Unknown ids cannot occur — every emitter uses a constant from this module —
/// but the lookup is total rather than panicking, and an unrecognised id reads
/// as the *stronger* answer: a gate whose severity nobody declared must not
/// quietly become an advisory.
#[must_use]
fn severity_of(id: &str) -> RuleSeverity {
    GATES
        .iter()
        .find(|(gate, _)| *gate == id)
        .map_or(RuleSeverity::Deny, |(_, severity)| *severity)
}

/// One integrity problem, as a pointer.
///
/// Carries the claim `id` because the acceptance asks for it by name — an
/// identifier the record's author chose, which is what a reader needs to find
/// the row. It never carries the claim's `source` text, its capture, or any
/// other field's content (rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Problem {
    /// The 1-based line of the record it sits on.
    pub line: usize,
    /// The stable gate id.
    pub id: &'static str,
    /// The claim id the row declares.
    pub claim: String,
    /// The earlier line, for [`DUPLICATE_CLAIM_ID`] — so one finding names
    /// **both** locations rather than leaving a reader to grep for the first.
    pub first: Option<usize>,
}

impl Problem {
    /// The severity this problem's gate carries.
    #[must_use]
    pub fn severity(&self) -> RuleSeverity {
        severity_of(self.id)
    }

    /// The pointer line the plain channel prints.
    #[must_use]
    pub fn line_text(&self) -> String {
        let mut text = format!("{STREAM}:{} {} claim={}", self.line, self.id, self.claim);
        if let Some(first) = self.first {
            // `write!` into a String is infallible; the result is discarded
            // rather than propagated, as `render.rs` does for the same reason.
            let _ = write!(text, " first={STREAM}:{first}");
        }
        text
    }

    /// This problem as an ordinary [`Finding`].
    ///
    /// A real finding rather than a bespoke verdict path, for `budget.rs`'s and
    /// `defects.rs`'s reason: the exit contract, `-J`, and the findings store all
    /// come free from being one, and a private path would re-implement each.
    ///
    /// [`FindingKind::Scope`] keyed on **gate id plus claim id**, never the line:
    /// a corpus is regenerated wholesale and every row's position moves, so a
    /// position-keyed identity would re-mint on every unrelated edit. The line
    /// still rides the finding as its pointer.
    #[must_use]
    pub fn finding(&self) -> Finding {
        let rule = self.id.to_owned();
        let identity = StoredIdentity::new(
            FindingKind::Scope,
            crate::identity::scope_fingerprint(&rule, &self.claim),
        );
        Finding {
            rule,
            severity: self.severity(),
            path: STREAM.to_owned(),
            line: Some(self.line),
            identity,
            // Engine-produced, so there is no `[[rule]]` row to read these from
            // (CLOUD-81). Re-parsing the claim stream is the check; the fix is
            // rewriting the claim it points at, which is a judgement rather than
            // an argv.
            check: crate::findings::Check::Reevaluate,
            remediation: Some(crate::findings::Remediation::NoFix(
                "rewrite or withdraw the design claim this points at".to_owned(),
            )),
        }
    }
}

/// Parse a JSONL claim stream, or the 1-based line of the first row that does
/// not parse.
///
/// The line number rather than the serde error is the whole failing return,
/// because a serde message quotes the offending bytes back and this gate reports
/// pointers (rule 4). Blank lines are skipped: a trailing newline is not a
/// record.
fn parse_lines(text: &str) -> Result<Vec<Claim>, usize> {
    let mut claims = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let claim: Claim = serde_json::from_str(line).map_err(|_| index + 1)?;
        claims.push(claim);
    }
    Ok(claims)
}

/// Parse a JSONL claim stream, reporting the 1-based line of the first bad row.
///
/// A malformed corpus is **exit 1, never 2**: the §7 table reserves the policy
/// verdict for a claim about the evidence, and "this stream is not the format"
/// is a claim about the invocation. Unlike `defects.rs`, where one bad row is a
/// finding beside the others, there is nothing else here to report — the corpus
/// *is* the input, so a row that does not parse leaves the audit with no object.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) naming the line, and no byte of it.
pub fn parse(text: &str) -> Result<Vec<Claim>> {
    parse_lines(text).map_err(|line| {
        UsageError::raise(format!(
            "design audit: stdin line {line} does not parse as a claim record"
        ))
    })
}

/// Every integrity problem in `claims`, under a per-capture ceiling of `cap`.
///
/// Returns them all rather than the first, so one run names everything to fix,
/// and sorted by `(line, id)` so the report is byte-stable for identical input
/// (§6). A pure function: the verdict is a function of the bytes and the cap,
/// and of nothing else.
#[must_use]
pub fn audit(claims: &[Claim], cap: usize) -> Vec<Problem> {
    let mut problems = Vec::new();
    // BTreeMap rather than a set: the duplicate finding names the FIRST
    // location too, so the earlier line has to be recoverable.
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();

    for (index, claim) in claims.iter().enumerate() {
        let line = index + 1;
        let mut raise = |id: &'static str, first: Option<usize>| {
            problems.push(Problem {
                line,
                id,
                claim: claim.id.clone(),
                first,
            });
        };

        match seen.get(claim.id.as_str()) {
            Some(first) => raise(DUPLICATE_CLAIM_ID, Some(*first)),
            None => {
                seen.insert(claim.id.as_str(), line);
            }
        }

        // The defect class of the record itself: no capture can attest an
        // absence, so `verified` over one is unsupportable however good the
        // evidence beside it looks.
        if claim.status == Status::Verified && claim.polarity == Polarity::Absence {
            raise(VERIFIED_ABSENCE, None);
        }
        // A status past `claimed` asserts that somebody checked. Nobody named is
        // the assertion with its subject missing.
        if claim.status != Status::Claimed && claim.verifier.is_none() {
            raise(VERIFIER_ABSENT, None);
        }
        if claim.claimant.is_none() {
            raise(CLAIMANT_ABSENT, None);
        }
        // Self-attestation, and only where both halves are named: an absent
        // claimant is CLAIMANT_ABSENT's finding, and reading `None == None` as
        // a match would report the same row twice for one defect.
        if claim.status == Status::Verified
            && claim.claimant.is_some()
            && claim.claimant == claim.verifier
        {
            raise(SELF_ATTESTED, None);
        }

        match claim.capture.as_ref() {
            Some(capture) => {
                if capture.byte_count > cap {
                    raise(CAPTURE_OVER_BUDGET, None);
                }
                match capture.bytes.as_ref() {
                    Some(bytes) => {
                        if hex_sha256(bytes.as_bytes()) != capture.digest.sha256 {
                            raise(DIGEST_MISMATCH, None);
                        }
                        if bytes.len() != capture.byte_count {
                            raise(BYTE_COUNT_MISMATCH, None);
                        }
                    }
                    // A digest with no bytes beside it: binding is not decidable
                    // either way, which on a claim asserting it was verified is
                    // exactly the CLOUD-76 shape — a record standing in for a
                    // capture that may never have succeeded.
                    None if claim.status == Status::Verified => {
                        raise(DIGEST_NOT_COMPUTABLE, None);
                    }
                    None => {}
                }
            }
            None if claim.status == Status::Verified => raise(DIGEST_NOT_COMPUTABLE, None),
            None => {}
        }
    }

    problems.sort_by_key(|problem| (problem.line, problem.id));
    problems
}

/// Whether `findings` fail the run at this rung of the ladder.
///
/// The first consumer of [`Strictness`], and it reads **all three ranks** rather
/// than special-casing `Strict`: each variant's own doc comment pins its
/// meaning, and a match that handled one rung would leave the other two meaning
/// whatever fell through. Promotion is [`crate::rules::any_blocking`] — the same
/// machinery `--fail-on-warning` drives — so `strict` needs no bespoke flag and
/// "advisory" has one definition.
///
/// `Permissive` cannot be selected by an override: `resolve` clamps strictness
/// raise-only, so reaching this arm takes a committed authority that says so.
#[must_use]
pub fn blocks(findings: &[Finding], strictness: Strictness, fail_on_warning: bool) -> bool {
    match strictness {
        Strictness::Permissive => false,
        Strictness::Standard => crate::rules::any_blocking(findings, fail_on_warning),
        Strictness::Strict => crate::rules::any_blocking(findings, true),
    }
}

/// One problem as it appears under `-J`.
///
/// Rendered through [`Problem`]'s own fields rather than by deriving `Serialize`
/// on the domain type, so the two channels cannot describe a finding
/// differently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct ProblemView {
    /// `-:<line>`, the same pointer the plain channel prints.
    pub at: String,
    /// The stable gate id.
    pub id: &'static str,
    /// The claim id the row declares.
    pub claim: String,
    /// The earlier location, for a duplicate id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first: Option<String>,
    /// `deny` or `warn` — which side of the promotion the gate sits on.
    pub severity: &'static str,
}

/// The `-J` document.
///
/// Emitted unconditionally, **including for a clean corpus**: JSON that is
/// sometimes absent is unparseable. The plain channel does the opposite and
/// prints nothing when clean (§6), which is the acceptance's own wording.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Report {
    /// Every problem, in the audit's stable order.
    pub problems: Vec<ProblemView>,
}

impl Report {
    /// Build the document from an audit's problems.
    #[must_use]
    pub fn new(problems: &[Problem]) -> Self {
        Report {
            problems: problems
                .iter()
                .map(|problem| ProblemView {
                    at: format!("{STREAM}:{}", problem.line),
                    id: problem.id,
                    claim: problem.claim.clone(),
                    first: problem.first.map(|first| format!("{STREAM}:{first}")),
                    severity: problem.severity().as_str(),
                })
                .collect(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// A capture whose digest and count are honest, so a test that is not about
    /// the capture gates does not trip them.
    fn capture(body: &str) -> Capture {
        Capture {
            digest: CaptureDigest {
                sha256: hex_sha256(body.as_bytes()),
            },
            byte_count: body.len(),
            bytes: Some(body.to_owned()),
        }
    }

    /// A claim that trips nothing: verified, existence-shaped, dual identities,
    /// a sound capture.
    fn clean(id: &str) -> Claim {
        Claim {
            id: id.to_owned(),
            status: Status::Verified,
            polarity: Polarity::Existence,
            source: "https://example.invalid/a".to_owned(),
            claimant: Some("author".to_owned()),
            verifier: Some("checker".to_owned()),
            capture: Some(capture("the captured evidence")),
        }
    }

    fn ids(problems: &[Problem]) -> Vec<&str> {
        problems.iter().map(|problem| problem.id).collect()
    }

    #[test]
    fn a_clean_corpus_raises_nothing() {
        let claims = [clean("a"), clean("b")];
        assert!(audit(&claims, DEFAULT_MAX_CAPTURE_BYTES).is_empty());
    }

    #[test]
    fn a_duplicate_id_names_both_locations() {
        let claims = [clean("a"), clean("b"), clean("a")];
        let problems = audit(&claims, DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(ids(&problems), [DUPLICATE_CLAIM_ID]);
        assert_eq!(problems[0].line, 3);
        assert_eq!(problems[0].first, Some(1));
        let text = problems[0].line_text();
        assert!(text.contains("-:3") && text.contains("-:1") && text.contains("claim=a"));
    }

    #[test]
    fn a_verified_absence_is_a_violation() {
        // The defect class this gate exists for: no capture can attest that
        // nothing does X, so `verified` over an absence is unsupportable.
        let mut claim = clean("a");
        claim.polarity = Polarity::Absence;
        let problems = audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(ids(&problems), [VERIFIED_ABSENCE]);
        assert_eq!(problems[0].severity(), RuleSeverity::Deny);
    }

    #[test]
    fn a_claimed_absence_is_fine() {
        // Polarity alone is never a defect — asserting an absence is ordinary.
        // What the gate refuses is the *record* saying it was verified.
        let mut claim = clean("a");
        claim.polarity = Polarity::Absence;
        claim.status = Status::Claimed;
        claim.capture = None;
        assert!(audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES).is_empty());
    }

    #[test]
    fn a_checked_status_with_no_verifier_is_a_violation() {
        for status in [Status::Verified, Status::Refuted] {
            let mut claim = clean("a");
            claim.status = status;
            claim.verifier = None;
            let problems = audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES);
            assert!(
                ids(&problems).contains(&VERIFIER_ABSENT),
                "{} asserts somebody checked, so somebody must be named",
                status.as_str()
            );
        }
        // …and `claimed` is the one status where no verifier is the honest state.
        let mut claim = clean("a");
        claim.status = Status::Claimed;
        claim.verifier = None;
        assert!(!ids(&audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES)).contains(&VERIFIER_ABSENT));
    }

    #[test]
    fn an_absent_claimant_is_an_advisory_and_is_not_also_self_attestation() {
        // `None == None` would make every unsigned claim self-attested too,
        // reporting one defect twice.
        let mut claim = clean("a");
        claim.claimant = None;
        claim.verifier = None;
        let problems = audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES);
        assert!(ids(&problems).contains(&CLAIMANT_ABSENT));
        assert!(!ids(&problems).contains(&SELF_ATTESTED));
        let claimant = problems
            .iter()
            .find(|problem| problem.id == CLAIMANT_ABSENT)
            .unwrap();
        assert_eq!(claimant.severity(), RuleSeverity::Warn);
    }

    #[test]
    fn a_verifier_who_is_the_claimant_is_an_advisory() {
        let mut claim = clean("a");
        claim.verifier = claim.claimant.clone();
        let problems = audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(ids(&problems), [SELF_ATTESTED]);
        assert_eq!(problems[0].severity(), RuleSeverity::Warn);
    }

    #[test]
    fn self_attestation_is_only_asked_of_a_verified_claim() {
        // A claim nobody has checked yet cannot have been checked by its author.
        let mut claim = clean("a");
        claim.status = Status::Claimed;
        claim.verifier = claim.claimant.clone();
        assert!(!ids(&audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES)).contains(&SELF_ATTESTED));
    }

    #[test]
    fn bytes_that_do_not_hash_to_the_digest_are_a_violation() {
        let mut claim = clean("a");
        claim.capture = Some(Capture {
            digest: CaptureDigest {
                sha256: hex_sha256(b"something else"),
            },
            byte_count: "the captured evidence".len(),
            bytes: Some("the captured evidence".to_owned()),
        });
        let problems = audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(ids(&problems), [DIGEST_MISMATCH]);
        assert_eq!(problems[0].severity(), RuleSeverity::Deny);
    }

    #[test]
    fn a_declared_count_that_disagrees_with_the_bytes_is_a_violation() {
        let mut claim = clean("a");
        let body = "the captured evidence";
        claim.capture = Some(Capture {
            digest: CaptureDigest {
                sha256: hex_sha256(body.as_bytes()),
            },
            byte_count: body.len() + 1,
            bytes: Some(body.to_owned()),
        });
        let problems = audit(&[claim], DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(ids(&problems), [BYTE_COUNT_MISMATCH]);
    }

    #[test]
    fn a_verified_claim_whose_binding_cannot_be_decided_is_an_advisory() {
        // Both spellings of not-computable: no capture at all, and a digest with
        // no bytes beside it. Neither is a pass.
        let mut without = clean("a");
        without.capture = None;
        assert_eq!(
            ids(&audit(&[without], DEFAULT_MAX_CAPTURE_BYTES)),
            [DIGEST_NOT_COMPUTABLE]
        );

        let mut bodyless = clean("a");
        bodyless.capture = Some(Capture {
            digest: CaptureDigest {
                sha256: hex_sha256(b"unreachable"),
            },
            byte_count: 11,
            bytes: None,
        });
        assert_eq!(
            ids(&audit(&[bodyless], DEFAULT_MAX_CAPTURE_BYTES)),
            [DIGEST_NOT_COMPUTABLE]
        );
    }

    #[test]
    fn the_budget_reads_the_declared_count_and_the_boundary_is_inclusive() {
        // Declared, not derived — which is what keeps the budget checkable for a
        // record carrying no bytes at all.
        let body = "the captured evidence";
        let mut claim = clean("a");
        claim.capture = Some(capture(body));

        assert!(
            audit(std::slice::from_ref(&claim), body.len()).is_empty(),
            "exactly at the ceiling is within it"
        );
        assert_eq!(ids(&audit(&[claim], body.len() - 1)), [CAPTURE_OVER_BUDGET]);
    }

    #[test]
    fn the_cap_clamp_is_tighten_only() {
        // Smaller is stricter for a budget, so §8's "may not weaken" means "may
        // not raise" — the direction reads backwards and is easy to invert.
        assert_eq!(effective_cap(None, None), DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(effective_cap(Some(1_000), None), 1_000);
        assert_eq!(effective_cap(Some(1_000), Some(500)), 500, "lowering wins");
        assert_eq!(
            effective_cap(Some(1_000), Some(9_000)),
            1_000,
            "a local file may not raise the ceiling"
        );
        assert_eq!(
            effective_cap(None, Some(99_999)),
            DEFAULT_MAX_CAPTURE_BYTES,
            "nor raise it above the engine default"
        );
    }

    #[test]
    fn the_ladder_is_total_over_its_three_ranks() {
        let violation = Problem {
            line: 1,
            id: VERIFIED_ABSENCE,
            claim: "a".to_owned(),
            first: None,
        }
        .finding();
        let advisory = Problem {
            line: 1,
            id: CLAIMANT_ABSENT,
            claim: "a".to_owned(),
            first: None,
        }
        .finding();

        // Permissive reports and never fails, whatever it found.
        assert!(!blocks(
            std::slice::from_ref(&violation),
            Strictness::Permissive,
            false
        ));
        assert!(!blocks(
            std::slice::from_ref(&violation),
            Strictness::Permissive,
            true
        ));
        // Standard fails on a violation and not on an advisory…
        assert!(blocks(
            std::slice::from_ref(&violation),
            Strictness::Standard,
            false
        ));
        assert!(!blocks(
            std::slice::from_ref(&advisory),
            Strictness::Standard,
            false
        ));
        // …unless `--fail-on-warning` promotes it, the existing machinery.
        assert!(blocks(
            std::slice::from_ref(&advisory),
            Strictness::Standard,
            true
        ));
        // Strict is Standard plus anything advisory, with no flag.
        assert!(blocks(&[advisory], Strictness::Strict, false));
        assert!(blocks(&[violation], Strictness::Strict, false));
        // Nothing found blocks at no rung.
        for strictness in [
            Strictness::Permissive,
            Strictness::Standard,
            Strictness::Strict,
        ] {
            assert!(!blocks(&[], strictness, true));
        }
    }

    #[test]
    fn every_gate_id_is_reachable() {
        // The census: a declared gate nothing produces is a taxonomy member with
        // no mechanism, which is the drift `defects.rs` set this idiom against.
        // One corpus, exercising every id at once.
        let body = "x";
        let claims = [
            // duplicate + verified-absence + self-attested + over-budget.
            Claim {
                id: "dup".to_owned(),
                status: Status::Claimed,
                polarity: Polarity::Existence,
                source: "s".to_owned(),
                claimant: Some("a".to_owned()),
                verifier: None,
                capture: None,
            },
            Claim {
                id: "dup".to_owned(),
                status: Status::Verified,
                polarity: Polarity::Absence,
                source: "s".to_owned(),
                claimant: Some("a".to_owned()),
                verifier: Some("a".to_owned()),
                capture: Some(Capture {
                    digest: CaptureDigest {
                        sha256: hex_sha256(b"nope"),
                    },
                    byte_count: 99,
                    bytes: Some(body.to_owned()),
                }),
            },
            // verifier-absent + claimant-absent + not-computable.
            Claim {
                id: "bare".to_owned(),
                status: Status::Refuted,
                polarity: Polarity::Existence,
                source: "s".to_owned(),
                claimant: None,
                verifier: None,
                capture: None,
            },
            // …and the not-computable half that needs a verified row.
            Claim {
                id: "unbound".to_owned(),
                status: Status::Verified,
                polarity: Polarity::Existence,
                source: "s".to_owned(),
                claimant: Some("a".to_owned()),
                verifier: Some("b".to_owned()),
                capture: None,
            },
        ];
        let problems = audit(&claims, 10);
        let raised = ids(&problems);
        for (gate, _) in GATES {
            assert!(raised.contains(gate), "no fixture raises {gate}");
        }
    }

    #[test]
    fn two_audits_over_the_same_corpus_agree_byte_for_byte() {
        let claims = [clean("a"), clean("a")];
        let first = audit(&claims, DEFAULT_MAX_CAPTURE_BYTES);
        let second = audit(&claims, DEFAULT_MAX_CAPTURE_BYTES);
        assert_eq!(first, second);
        assert_eq!(
            serde_json::to_string(&Report::new(&first)).unwrap(),
            serde_json::to_string(&Report::new(&second)).unwrap()
        );
    }

    #[test]
    fn a_malformed_row_names_its_line_and_no_byte_of_it() {
        let secret = "SENTINEL-never-echoed";
        let text = format!("{{\"id\":\"a\"}}\n{{\"id\":\"{secret}\", oops\n");
        let err = parse(&text).expect_err("a malformed corpus refuses");
        let message = err.to_string();
        assert!(message.contains("line 1"), "{message}");
        assert!(!message.contains(secret), "the row's bytes never travel");
    }

    #[test]
    fn an_unknown_enum_token_is_a_parse_error_not_a_weakest_variant() {
        // The whole point of closed enums: a corpus written against a newer
        // schema is refused, never audited as `claimed`.
        let text =
            "{\"id\":\"a\",\"status\":\"attested\",\"polarity\":\"existence\",\"source\":\"s\"}\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn an_unknown_field_is_a_parse_error() {
        let text = "{\"id\":\"a\",\"status\":\"claimed\",\"polarity\":\"existence\",\"source\":\"s\",\"extra\":1}\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn blank_lines_are_not_records() {
        let text = "\n{\"id\":\"a\",\"status\":\"claimed\",\"polarity\":\"existence\",\"source\":\"s\",\"claimant\":\"a\"}\n\n";
        assert_eq!(parse(text).unwrap().len(), 1);
    }

    #[test]
    fn every_token_is_distinct_within_its_vocabulary() {
        for tokens in [
            Status::ALL.iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            Polarity::ALL.iter().map(|p| p.as_str()).collect::<Vec<_>>(),
        ] {
            let mut unique = tokens.clone();
            unique.sort_unstable();
            unique.dedup();
            assert_eq!(tokens.len(), unique.len());
        }
    }

    #[test]
    fn a_findings_identity_is_stable_across_a_moved_row() {
        // Keyed on gate id plus claim id, never the line: a corpus is
        // regenerated wholesale, so a position-keyed identity would re-mint on
        // every unrelated edit.
        let at_one = Problem {
            line: 1,
            id: VERIFIED_ABSENCE,
            claim: "a".to_owned(),
            first: None,
        }
        .finding();
        let at_nine = Problem {
            line: 9,
            id: VERIFIED_ABSENCE,
            claim: "a".to_owned(),
            first: None,
        }
        .finding();
        assert_eq!(at_one.identity, at_nine.identity);
    }
}
