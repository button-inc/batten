//! The judge's payload-privacy boundary (CLOUD-135) — what may be sent to a
//! model.
//!
//! Batten's law is that sensitive or bulky content is reduced to a pointer and
//! never dumped into a model's context. The optional LLM judge (CLOUD-56) is the
//! one component that inverts it: to reach a verdict it sends *something*
//! outward. This module is what that something is governed by, and it exists
//! **before** the judge on purpose — a boundary written after the code it
//! bounds is a boundary the code has already crossed.
//!
//! ## Why the bar is high rather than balanced
//!
//! The judge's verdict is advisory-only, structurally unable to produce a
//! blocking exit code (house style §0.3). So content that crosses this boundary
//! buys a signal that cannot even block — which is not an argument for a
//! careful default, it is an argument for a **refusing** one. Nothing crosses
//! unless config names the class.
//!
//! ## The two ways a span becomes protected
//!
//! [`Attribution`] is a structural match, never an inference:
//!
//! * its path matches a glob in the committed `protected` set, or
//! * **it carries no path provenance at all**.
//!
//! The second is the fail-closed half and the one worth stating twice. A span
//! with nowhere to attribute it cannot be shown to be safe, and "cannot be shown
//! to be safe" resolves to protected here rather than to sent. Every silent
//! egress bug in this shape is a default that read absent as permitted.
//!
//! ## One protected member refuses the WHOLE invocation
//!
//! Not the span — the invocation. [`assemble`] returns [`Refusal::Protected`]
//! and the caller exits `1`, naming the rule and the count.
//!
//! An earlier landing withheld protected spans individually behind a config key
//! (`over_protected = "raw" | "pointer"`), and CLOUD-135's `DoD` audit removed it:
//! that key is verbatim the issue's own **rejected** alternative — "a committed
//! opt-in key for protected egress … a widening surface that purchases no
//! enforcement power. If a consumer ever needs it, that is a new recorded
//! decision, not a latent key." Per-span withholding also quietly changes what
//! the judge is judging: the row named a set of files, and silently sending a
//! subset means the verdict is about content the config never described. Refusal
//! is the only posture that keeps the verdict honest and the bytes home.
//!
//! ## What a refusal leaves behind
//!
//! A pointer and a hash, never nothing. The hash ([`crate::identity::
//! judge_fingerprint`]) lets a caller reference content it did not send — two
//! findings over identical withheld bytes are visibly the same content — without
//! the bytes leaving. It reuses the one length-prefixed construction rather than
//! minting a second hash of the same bytes.
//!
//! ## The cap refuses whole, and never truncates
//!
//! [`Judge::max_payload_bytes`] defaults to [`DEFAULT_MAX_PAYLOAD_BYTES`]. Over
//! it, the invocation is refused. Truncating would be worse than refusing: the
//! judge would return a verdict about a prefix while the record says it judged
//! the row — a quiet disagreement between what was named and what was read.
//!
//! The clamp is **tighten-only** ([`effective_cap`]): a lower local value wins,
//! a higher one is ignored. Today `resolve` does not layer `[judge]` at all,
//! which is strictly stronger than tighten-only — nothing local reaches it — so
//! the clamp is the semantics waiting for the day it does.
//!
//! ## What this module does not do
//!
//! [`assemble`] performs no egress and spawns nothing: it is config types plus
//! pure functions, so a local model stays available by construction and there is
//! no network path in it to review.
//!
//! ## The execution half (CLOUD-56)
//!
//! [`argv`] and [`Verdict`] are the wiring the paragraph above used to defer.
//! They keep the same posture: the payload crosses on the judge command's
//! **stdin** — never argv, which is world-readable process state, and never a
//! temp file — and the engine reads the command's **exit code only**.
//!
//! That last point is the whole gate/judge line (CLOUD-93). A judge's prose is
//! not parsed, matched, or inspected: if it were, the model's classification
//! would re-enter the engine as a decision input, which is the thing
//! non-negotiable rule 3 forbids. An exit code is the same channel every spawned
//! predicate in this engine already speaks, and it carries exactly three bits of
//! meaning — [`Verdict`] enumerates them.
//!
//! And a verdict, however it lands, is **advisory**: nothing here constructs a
//! [`crate::rules::Finding`], so `any_blocking` and `--fail-on-warning` cannot
//! see a judge outcome. The advisory surface is unable to block by type rather
//! than by policy.

use std::process::Command;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::identity;
use crate::rules::PathSet;

/// The `[judge]` table: what the judge may put in a model call.
///
/// Every field defaults to the refusing reading, so a `[judge]` table that
/// merely exists sends nothing but pointers and hashes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Judge {
    /// The content classes admitted **raw** into a model call. Empty — the
    /// default — means pointer-only: no span bytes cross at all.
    ///
    /// A class named here is admitted and nothing else is. There is deliberately
    /// no "all" spelling: a config that wants both classes names both, so the
    /// diff that widens the boundary shows what it widened.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub raw: Vec<PayloadClass>,
    /// The ceiling on assembled payload bytes. Absent means
    /// [`DEFAULT_MAX_PAYLOAD_BYTES`].
    ///
    /// There is deliberately **no** key for what happens over the `protected`
    /// set: one protected member refuses the invocation, full stop. See the
    /// module docs for why that key was removed rather than defaulted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_payload_bytes: Option<usize>,
    /// The judge command, as a template. The first whitespace-separated token is
    /// a program on the operator's `PATH`, **executed directly and never through
    /// a shell** — so this is data a reviewer can read, not a script.
    ///
    /// Absent is legal on its own: a `[judge]` table predates the judge that
    /// reads it (CLOUD-135 landed first), and a repository that declared a
    /// boundary and no command must keep loading. It is a judge **row** that
    /// cannot resolve without one — see [`argv`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
    /// The model the operator's command should use, substituted into [`Judge::run`]
    /// at each `{{model}}` placeholder.
    ///
    /// **Opaque to the engine**: never parsed, never validated against a list,
    /// never used to decide anything. Batten has no opinion about which model a
    /// consumer judges with, and a build that shipped a roster would be stating
    /// one — plus going stale (non-negotiable rule 1: the fact is the consumer's).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
}

/// The `{{model}}` placeholder [`Judge::model`] substitutes for in [`Judge::run`].
///
/// A template naming it with no `model` declared is a usage error rather than a
/// literal `{{model}}` argv token: a command invoked with the placeholder still
/// in it would ask the operator's judge to evaluate against a model called
/// `{{model}}`, and whatever that returns is not a verdict about anything.
pub const MODEL_PLACEHOLDER: &str = "{{model}}";

/// The argv a judge row's command resolves to: program first, arguments after.
///
/// Splitting on whitespace is the same reading [`crate::rules::Rule::program`]
/// gives a `command` rule's `check`, and for the same reason — one authority for
/// "which token is the program", so a `doctor` PATH probe and the runner can
/// never disagree about which binary they are talking about.
///
/// # Errors
///
/// [`UsageError`] (→ exit `1`) when no `[judge]` table is declared, when `run` is
/// absent, empty or whitespace-only, or when the template names
/// [`MODEL_PLACEHOLDER`] with no `model` to put there. Each names the judge row,
/// because a config error must point at the row that has to change.
pub fn argv(rule: &str, judge: Option<&Judge>) -> anyhow::Result<Vec<String>> {
    let Some(template) = judge.and_then(|judge| judge.run.as_deref()) else {
        return Err(UsageError::raise(format!(
            "rule {rule}: kind \"judge\" needs a `[judge]` table declaring `run`; without a \
             command there is nothing to ask"
        )));
    };
    let model = judge.and_then(|judge| judge.model.as_deref());
    if template.contains(MODEL_PLACEHOLDER) && model.is_none() {
        return Err(UsageError::raise(format!(
            "rule {rule}: `[judge].run` names {MODEL_PLACEHOLDER} and `[judge].model` is not set"
        )));
    }
    let model = model.unwrap_or_default();
    let argv: Vec<String> = template
        .split_whitespace()
        .map(|token| token.replace(MODEL_PLACEHOLDER, model))
        .collect();
    if argv.is_empty() {
        return Err(UsageError::raise(format!(
            "rule {rule}: `[judge].run` is empty; a command with no program cannot be invoked"
        )));
    }
    Ok(argv)
}

/// What a judge command's exit code meant.
///
/// Three values because the channel carries three facts, and the third is the
/// one a naive mapping loses: a judge that **failed to run properly** is not a
/// judge that passed. Reading any non-zero as "raise" or any non-two as "clean"
/// both convert a plumbing failure into a verdict, which is the false-green this
/// engine exists to catch — so an odd exit registers, loudly, as unresolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// `0`: the judge found nothing. No finding registers.
    Clean,
    /// `2`: the judge raised something. An advisory finding registers at the
    /// row's tier. The same `2` every other predicate in this engine speaks —
    /// and still not a blocking one, because it never becomes a `Finding`.
    Raised,
    /// Anything else, including a signal: the judge did not deliver a verdict.
    /// An `unresolved` finding registers naming the code.
    Unresolved(i32),
}

impl Verdict {
    /// The exit code a judge command returned, read as a verdict.
    ///
    /// Total over `i32` by construction, and `None` — a process killed by a
    /// signal, which `ExitStatus::code` reports as no code — is
    /// [`Verdict::Unresolved`] with the conventional `128 + signal` stand-in
    /// spelled as a plain sentinel: a judge the kernel killed said nothing, and
    /// "said nothing" is exactly what unresolved means.
    #[must_use]
    pub const fn of(code: Option<i32>) -> Verdict {
        match code {
            Some(0) => Verdict::Clean,
            Some(2) => Verdict::Raised,
            Some(other) => Verdict::Unresolved(other),
            None => Verdict::Unresolved(SIGNALLED),
        }
    }

    /// Whether this verdict puts a record in the store.
    #[must_use]
    pub const fn registers(self) -> bool {
        !matches!(self, Verdict::Clean)
    }

    /// The stable token for the record and machine output (§6).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Raised => "raised",
            Verdict::Unresolved(_) => "unresolved",
        }
    }
}

/// The stand-in code for "killed by a signal, so it reported none".
pub const SIGNALLED: i32 = -1;

/// Run `argv` with `payload` on stdin, and read the exit code as a [`Verdict`].
///
/// The payload goes to **stdin** and nowhere else (CLOUD-135 decision 4), and
/// the program is spawned directly rather than through a shell, so nothing in
/// `run` is word-split, globbed, or interpolated by anything but [`argv`] above.
///
/// The judge's stdout and stderr are inherited by nothing and read by nothing:
/// they are captured and dropped. Capturing keeps a chatty model's prose off
/// Batten's own channels (§6, rule 4); dropping is what makes "the engine reads
/// the exit code only" true rather than aspirational.
///
/// # Errors
///
/// [`UsageError`] (→ exit `1`) when the program cannot be spawned — the
/// `command`-kind precedent: a program a config names and `PATH` does not have is
/// a config error about the invocation, never a policy verdict about the repo.
pub fn invoke(rule: &str, argv: &[String], payload: &[u8]) -> anyhow::Result<Verdict> {
    use std::io::Write as _;

    let Some((program, args)) = argv.split_first() else {
        return Err(UsageError::raise(format!(
            "rule {rule}: `[judge].run` resolved to no program"
        )));
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| {
            UsageError::raise(format!(
                "rule {rule}: cannot run judge program `{program}`: {err}"
            ))
        })?;
    // Take the pipe before waiting: a child blocked writing to a full stdout
    // pipe while we block on `wait` is the classic deadlock, and the null sinks
    // above are what make it impossible here.
    if let Some(mut stdin) = child.stdin.take() {
        // A judge that closed stdin early is not a failure to report *here* —
        // it is a judge that chose to answer without reading, and its exit code
        // is still its answer. Anything else would let a broken pipe outrank a
        // verdict the command actually delivered.
        let _ = stdin.write_all(payload);
    }
    let status = child.wait().map_err(|err| {
        UsageError::raise(format!(
            "rule {rule}: judge program `{program}` could not be waited on: {err}"
        ))
    })?;
    Ok(Verdict::of(status.code()))
}

/// The engine's payload ceiling when a row names none.
///
/// 16 KiB, the precedent of the argv-batching bound: large enough for a rule's
/// criteria plus a handful of matched files, small enough that an accidental
/// whole-tree glob refuses instead of shipping the repository to a model.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 16_384;

/// The cap actually in force, given the authority's value and a local one.
///
/// **Tighten-only**: the minimum wins, so a local file may lower the ceiling and
/// a local file that tries to raise it changes nothing. A raise-only clamp reads
/// backwards here and is worth stating: for a *budget* smaller is stricter, so
/// the §8 "may not weaken" rule means "may not increase".
#[must_use]
pub fn effective_cap(authority: Option<usize>, local: Option<usize>) -> usize {
    let base = authority.unwrap_or(DEFAULT_MAX_PAYLOAD_BYTES);
    match local {
        Some(local) => base.min(local),
        None => base,
    }
}

/// A class of content that could cross into a model call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PayloadClass {
    /// The bytes of one matched span.
    SpanText,
    /// The bytes of a whole file.
    FileText,
}

impl PayloadClass {
    /// Every class, so a census cannot go stale — the `Effect::ALL` idiom.
    pub const ALL: &'static [PayloadClass] = &[PayloadClass::SpanText, PayloadClass::FileText];

    /// The stable token, used in config, output, and the hash preimage.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            PayloadClass::SpanText => "span_text",
            PayloadClass::FileText => "file_text",
        }
    }
}

/// One piece of content a caller offers the judge, with the provenance that
/// decides whether it may cross.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Span {
    /// The rule that produced it.
    pub rule: String,
    /// The repo-relative path it came from, `/`-separated. `None` is the
    /// fail-closed case: no provenance means protected.
    pub path: Option<String>,
    /// The 1-based line, when the origin locates one.
    pub line: Option<usize>,
    /// What kind of content this is.
    pub class: PayloadClass,
    /// The bytes themselves. This type is the only place they appear — a
    /// [`Payload`] carries them only where config admitted the class.
    pub bytes: Vec<u8>,
}

impl Span {
    /// Whether this span is protected, and why.
    ///
    /// An exact structural match, never an inference: the path is tested against
    /// the committed set's globs, and an absent path is protected outright.
    #[must_use]
    pub fn attribution(&self, protected: &PathSet) -> Attribution {
        match &self.path {
            None => Attribution::NoProvenance,
            Some(path) if protected.contains(path) => Attribution::Protected,
            Some(_) => Attribution::Unprotected,
        }
    }
}

/// Why a span is or is not protected. Three values rather than a boolean,
/// because "protected because the policy says so" and "protected because we
/// could not tell" are different facts about the same verdict, and a caller
/// auditing the boundary needs to see which one it got.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Attribution {
    /// The path is outside the protected set.
    Unprotected,
    /// The path matches the protected set.
    Protected,
    /// No path provenance: protected by the fail-closed rule.
    NoProvenance,
}

impl Attribution {
    /// Whether this attribution withholds by default.
    #[must_use]
    pub const fn is_protected(self) -> bool {
        matches!(self, Attribution::Protected | Attribution::NoProvenance)
    }
}

/// One span as it appears in a payload.
///
/// [`PayloadEntry::text`] is the **only** field that can carry content, and it
/// is `Some` only where config named the class. Everything else is a pointer, a
/// class name, or a hash — so a caller that serializes this type cannot leak by
/// accident, only by configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct PayloadEntry {
    /// The rule that produced the span.
    pub rule: String,
    /// `path:line`, `path`, or `None` when the span had no provenance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pointer: Option<String>,
    /// The class of the content this entry stands for.
    pub class: &'static str,
    /// Why it was or was not withheld.
    pub attribution: Attribution,
    /// The identity of the bytes, present whether or not they were sent — so a
    /// withheld entry still says *which* content it withheld.
    pub hash: String,
    /// The bytes, present only where config admitted this class.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
}

/// The judge row's own committed text — the *rule* payload class.
///
/// Its own type because it is the one class that is **not** repo content: it is
/// the config author's own words, already committed to `batten.toml`, so it
/// carries no egress question at all and always crosses. Separating it from
/// [`Span`] is what makes "the constructor admits exactly three classes"
/// checkable by reading the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct RuleText {
    /// The judge row's `id`.
    pub id: String,
    /// The judge row's `criteria` — what the model is being asked.
    pub criteria: String,
}

/// What a judge model call may carry.
///
/// Byte-identical for identical input: entries stay in the caller's order and no
/// field derives from the clock, the environment, or where the repository lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Payload {
    /// The *rule* class: the row's own committed id and criteria.
    pub rule: RuleText,
    /// The entries, in the order the caller supplied them.
    pub entries: Vec<PayloadEntry>,
    /// How many entries carry content.
    pub sent: usize,
    /// How many are pointer-and-hash only.
    pub withheld: usize,
}

/// Why an assembly refused. Every variant is pointer-only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum Refusal {
    /// At least one offered span is protected, so nothing is assembled.
    Protected {
        /// The judge row that asked.
        rule: String,
        /// How many offered spans were protected. A count, never the paths —
        /// which file is secret is itself worth not printing.
        count: usize,
    },
    /// The assembled payload exceeds the cap in force.
    OverCap {
        /// The judge row that asked.
        rule: String,
        /// What it would have been.
        bytes: usize,
        /// The ceiling it broke.
        cap: usize,
    },
}

impl Refusal {
    /// The pointer-only diagnostic a caller prints before exiting `1`.
    #[must_use]
    pub fn line(&self) -> String {
        match self {
            Refusal::Protected { rule, count } => format!(
                "judge {rule}: refused — {count} protected span(s) offered; protected content \
                 never crosses"
            ),
            Refusal::OverCap { rule, bytes, cap } => {
                format!("judge {rule}: refused — payload {bytes} bytes over the {cap}-byte cap")
            }
        }
    }

    /// The disposition token this refusal records.
    #[must_use]
    pub const fn disposition(&self) -> &'static str {
        match self {
            Refusal::Protected { .. } => "refused-protected",
            Refusal::OverCap { .. } => "refused-over-cap",
        }
    }
}

/// The pointer-only record of one assembly, refused or crossed.
///
/// Carries **no payload bytes** — a count and a hash stand for them, which is
/// what lets the record be stored and reported under the same output law as
/// every other Batten emission (rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct InvocationRecord {
    /// The judge row.
    pub rule: String,
    /// How many bytes the payload was, or would have been.
    pub bytes: usize,
    /// SHA-256 over the serialized payload, so two identical calls are visibly
    /// identical without either being reproduced.
    pub sha256: String,
    /// How many files the row's glob matched.
    pub matched_files: usize,
    /// `crossed`, or the refusal's token.
    pub disposition: &'static str,
}

/// A successful assembly: the bytes to send, and the record of having sent them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Assembled {
    /// The payload, as the caller will serialize it.
    pub payload: Payload,
    /// The serialized bytes — what actually crosses, and what `bytes`/`sha256`
    /// in the record are over. Handed back rather than re-derived so the record
    /// cannot describe different bytes than the ones sent.
    pub serialized: Vec<u8>,
    /// The pointer-only record.
    pub record: InvocationRecord,
}

/// Assemble the payload for `rule` over `spans`, under `protected` and `judge`.
///
/// A pure function of its inputs — no I/O, no clock, no environment — which is
/// what lets the boundary be tested exhaustively rather than observed.
///
/// The order is load-bearing: **protection is decided before any byte is
/// admitted**, so a protected member refuses without its content ever entering a
/// payload value, and the cap is checked on the assembled bytes so it bounds
/// what would actually cross.
///
/// An absent `[judge]` is the same as a `[judge]` that admits nothing: the rule
/// text, pointers and hashes, and no span content.
///
/// # Errors
///
/// [`Refusal::Protected`] when any offered span is protected or has no
/// provenance; [`Refusal::OverCap`] when the assembled bytes exceed the cap.
/// Both are usage errors at the caller (exit 1), never a policy verdict.
pub fn assemble(
    rule: &RuleText,
    spans: &[Span],
    protected: &PathSet,
    judge: Option<&Judge>,
    cap: usize,
) -> Result<Assembled, Refusal> {
    // First, and before anything is read into a payload: one protected member
    // refuses the whole invocation.
    let protected_count = spans
        .iter()
        .filter(|span| span.attribution(protected).is_protected())
        .count();
    if protected_count > 0 {
        return Err(Refusal::Protected {
            rule: rule.id.clone(),
            count: protected_count,
        });
    }

    let raw = judge.map_or(&[][..], |judge| judge.raw.as_slice());
    let mut entries = Vec::with_capacity(spans.len());
    let mut sent = 0;
    for span in spans {
        // Only the class gate remains here: the protection gate above already
        // refused the invocation, so every span reaching this loop is
        // attributable and unprotected.
        let admitted = raw.contains(&span.class);
        if admitted {
            sent += 1;
        }
        entries.push(PayloadEntry {
            rule: span.rule.clone(),
            pointer: pointer_of(span),
            class: span.class.as_str(),
            attribution: span.attribution(protected),
            hash: identity::judge_fingerprint(span.class.as_str(), &span.bytes).to_hex(),
            // `from_utf8_lossy`: a payload is a model call, so it must be text.
            // Lossy rather than a refusal because the alternative — dropping a
            // span config explicitly admitted — would be a silent narrowing, and
            // the hash above still identifies the exact original bytes.
            text: admitted.then(|| String::from_utf8_lossy(&span.bytes).into_owned()),
        });
    }

    let payload = Payload {
        rule: rule.clone(),
        withheld: entries.len() - sent,
        entries,
        sent,
    };
    // Serialization cannot fail for this type — every field is a string, a
    // number, or a Vec of the same — but the boundary must not panic, so an
    // unexpected failure refuses at the cap rather than unwrapping.
    let serialized = serde_json::to_vec(&payload).unwrap_or_default();
    if serialized.len() > cap {
        return Err(Refusal::OverCap {
            rule: rule.id.clone(),
            bytes: serialized.len(),
            cap,
        });
    }

    let record = InvocationRecord {
        rule: rule.id.clone(),
        bytes: serialized.len(),
        sha256: identity::judge_fingerprint("payload", &serialized).to_hex(),
        matched_files: spans.len(),
        disposition: "crossed",
    };
    Ok(Assembled {
        payload,
        serialized,
        record,
    })
}

/// The pointer for a span: `path:line`, `path`, or nothing to point at.
fn pointer_of(span: &Span) -> Option<String> {
    let path = span.path.as_ref()?;
    Some(match span.line {
        Some(line) => format!("{path}:{line}"),
        None => path.clone(),
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"AKIAIOSFODNN7EXAMPLE trailing-secret-bytes";
    const UNMATCHED: &[u8] = b"UNMATCHED-FILE-SENTINEL-nothing-selected-this";
    const ENV_SENTINEL: &[u8] = b"ENV-VALUE-SENTINEL-never-a-payload-input";

    fn protected_set() -> PathSet {
        PathSet::includes("protected", &["secrets/**".to_owned()]).unwrap()
    }

    fn rule_text() -> RuleText {
        RuleText {
            id: "a-rule".to_owned(),
            criteria: "does this read as intentional".to_owned(),
        }
    }

    fn span(path: Option<&str>, class: PayloadClass, bytes: &[u8]) -> Span {
        Span {
            rule: "a-rule".to_owned(),
            path: path.map(ToOwned::to_owned),
            line: Some(7),
            class,
            bytes: bytes.to_vec(),
        }
    }

    /// The assertion the acceptance actually asks for: search the serialized
    /// bytes for the needle.
    fn carries(bytes: &[u8], needle: &[u8]) -> bool {
        bytes.windows(needle.len()).any(|window| window == needle)
    }

    fn assemble_ok(spans: &[Span], judge: Option<&Judge>) -> Assembled {
        assemble(
            &rule_text(),
            spans,
            &protected_set(),
            judge,
            DEFAULT_MAX_PAYLOAD_BYTES,
        )
        .expect("assembly succeeds")
    }

    #[test]
    fn one_protected_span_refuses_the_whole_invocation() {
        // Decision 2, and the clause the DoD audit reopened this issue for. Not
        // "this span is withheld" — the invocation is refused, so no payload
        // value containing the other spans exists either.
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"ordinary"),
            span(Some("secrets/prod.env"), PayloadClass::SpanText, SECRET),
        ];
        // Even with the class admitted raw: admitting a class is not admitting a
        // protected file.
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        let refusal = assemble(
            &rule_text(),
            &spans,
            &protected_set(),
            Some(&judge),
            DEFAULT_MAX_PAYLOAD_BYTES,
        )
        .expect_err("a protected member refuses");

        assert_eq!(
            refusal,
            Refusal::Protected {
                rule: "a-rule".to_owned(),
                count: 1,
            }
        );
        let line = refusal.line();
        assert!(line.contains("a-rule") && line.contains('1'));
        assert!(
            !carries(line.as_bytes(), SECRET) && !carries(line.as_bytes(), b"secrets/prod.env"),
            "the diagnostic is a count, never the bytes or even the path: {line}"
        );
    }

    #[test]
    fn a_span_with_no_provenance_refuses_too() {
        // The fail-closed half: nothing marked it protected, and nothing could
        // show it was safe either.
        let spans = [span(None, PayloadClass::SpanText, SECRET)];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        assert!(matches!(
            assemble(
                &rule_text(),
                &spans,
                &PathSet::empty(),
                Some(&judge),
                DEFAULT_MAX_PAYLOAD_BYTES
            ),
            Err(Refusal::Protected { count: 1, .. })
        ));
    }

    #[test]
    fn a_clean_payload_carries_the_criteria_and_the_matched_bytes_and_no_sentinel() {
        // The acceptance's positive-and-negative byte scan, in one place.
        let spans = [span(Some("src/a.rs"), PayloadClass::SpanText, b"the span")];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        let assembled = assemble_ok(&spans, Some(&judge));

        assert!(
            carries(&assembled.serialized, b"does this read as intentional"),
            "the rule class crosses: it is the config author's own committed words"
        );
        assert!(carries(&assembled.serialized, b"the span"));
        for sentinel in [SECRET, UNMATCHED, ENV_SENTINEL] {
            assert!(
                !carries(&assembled.serialized, sentinel),
                "a sentinel the constructor was never offered cannot appear"
            );
        }
    }

    #[test]
    fn the_raw_opt_in_admits_exactly_the_named_class_and_nothing_else() {
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"the span"),
            span(Some("src/b.rs"), PayloadClass::FileText, b"the whole file"),
        ];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        let assembled = assemble_ok(&spans, Some(&judge));

        assert_eq!(assembled.payload.sent, 1);
        assert_eq!(
            assembled.payload.entries[0].text.as_deref(),
            Some("the span")
        );
        assert!(
            assembled.payload.entries[1].text.is_none(),
            "a class the config did not name does not ride in on one it did"
        );
        assert!(!carries(&assembled.serialized, b"the whole file"));
    }

    #[test]
    fn nothing_crosses_by_default() {
        let spans = [span(Some("src/a.rs"), PayloadClass::SpanText, b"the span")];
        for judge in [
            None,
            Some(Judge {
                raw: Vec::new(),
                max_payload_bytes: None,
                run: None,
                model: None,
            }),
        ] {
            let assembled = assemble_ok(&spans, judge.as_ref());
            assert_eq!(
                assembled.payload.sent, 0,
                "an unconfigured judge sends no content"
            );
            assert!(!carries(&assembled.serialized, b"the span"));
            assert!(
                carries(&assembled.serialized, b"does this read as intentional"),
                "the rule class still crosses — it is not repo content"
            );
        }
    }

    #[test]
    fn the_cap_refuses_whole_and_the_boundary_is_inclusive() {
        let spans = [span(Some("src/a.rs"), PayloadClass::SpanText, b"content")];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        let exact = assemble_ok(&spans, Some(&judge)).serialized.len();

        // Exactly at the cap assembles.
        assert!(
            assemble(&rule_text(), &spans, &protected_set(), Some(&judge), exact).is_ok(),
            "exactly at the cap is within it"
        );

        // One byte under refuses — whole, never truncated.
        let refusal = assemble(
            &rule_text(),
            &spans,
            &protected_set(),
            Some(&judge),
            exact - 1,
        )
        .expect_err("over the cap refuses");
        assert_eq!(
            refusal,
            Refusal::OverCap {
                rule: "a-rule".to_owned(),
                bytes: exact,
                cap: exact - 1,
            }
        );
        assert!(!carries(refusal.line().as_bytes(), b"content"));
    }

    #[test]
    fn the_cap_clamp_is_tighten_only() {
        // Smaller is stricter for a budget, so §8's "may not weaken" means "may
        // not raise" here — the direction reads backwards and is easy to invert.
        assert_eq!(effective_cap(None, None), DEFAULT_MAX_PAYLOAD_BYTES);
        assert_eq!(effective_cap(Some(1_000), None), 1_000);
        assert_eq!(effective_cap(Some(1_000), Some(500)), 500, "lowering wins");
        assert_eq!(
            effective_cap(Some(1_000), Some(9_000)),
            1_000,
            "a local file may not raise the ceiling"
        );
        assert_eq!(
            effective_cap(None, Some(99_999)),
            DEFAULT_MAX_PAYLOAD_BYTES,
            "nor raise it above the engine default"
        );
    }

    #[test]
    fn the_record_is_pointer_only_and_never_carries_payload_bytes() {
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"the span"),
            span(Some("src/b.rs"), PayloadClass::SpanText, b"more content"),
        ];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        let assembled = assemble_ok(&spans, Some(&judge));
        let record = serde_json::to_vec(&assembled.record).unwrap();

        assert_eq!(assembled.record.rule, "a-rule");
        assert_eq!(assembled.record.matched_files, 2);
        assert_eq!(assembled.record.bytes, assembled.serialized.len());
        assert_eq!(assembled.record.sha256.len(), 64);
        assert_eq!(assembled.record.disposition, "crossed");
        for needle in [
            &b"the span"[..],
            &b"more content"[..],
            b"does this read as intentional",
        ] {
            assert!(
                !carries(&record, needle),
                "the record stands for the payload, it does not reproduce it"
            );
        }
    }

    #[test]
    fn two_assemblies_over_the_same_input_are_byte_identical() {
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"ordinary"),
            span(Some("src/b.rs"), PayloadClass::FileText, b"a whole file"),
        ];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            max_payload_bytes: None,
            run: None,
            model: None,
        };
        let first = assemble_ok(&spans, Some(&judge));
        let second = assemble_ok(&spans, Some(&judge));
        assert_eq!(first.serialized, second.serialized);
        assert_eq!(
            serde_json::to_vec(&first.record).unwrap(),
            serde_json::to_vec(&second.record).unwrap()
        );
    }

    #[test]
    fn the_same_bytes_under_two_classes_are_two_identities() {
        // A hash stands for what was withheld, and "this span" and "this whole
        // file" are different claims even when the bytes agree.
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"same"),
            span(Some("src/a.rs"), PayloadClass::FileText, b"same"),
        ];
        let assembled = assemble_ok(&spans, None);
        assert_ne!(
            assembled.payload.entries[0].hash,
            assembled.payload.entries[1].hash
        );
    }

    #[test]
    fn every_class_has_a_token_and_they_are_distinct() {
        let tokens: Vec<&str> = PayloadClass::ALL.iter().map(|c| c.as_str()).collect();
        let mut unique = tokens.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(tokens.len(), unique.len(), "class tokens must be distinct");
    }

    // --- the execution half (CLOUD-56) -------------------------------------

    fn runner(run: &str, model: Option<&str>) -> Judge {
        Judge {
            raw: Vec::new(),
            max_payload_bytes: None,
            run: Some(run.to_owned()),
            model: model.map(ToOwned::to_owned),
        }
    }

    #[test]
    fn the_verdict_map_is_total_and_only_two_codes_mean_anything() {
        // The load-bearing arm is the third: every code that is not 0 or 2 is
        // unresolved, so a judge that crashed can never read as a pass. Swept
        // over the whole byte range rather than three hand-picked codes,
        // because "some other non-zero" is exactly where a naive `!= 0` maps a
        // plumbing failure onto a verdict.
        assert_eq!(Verdict::of(Some(0)), Verdict::Clean);
        assert_eq!(Verdict::of(Some(2)), Verdict::Raised);
        for code in -8..=255 {
            if code == 0 || code == 2 {
                continue;
            }
            assert_eq!(
                Verdict::of(Some(code)),
                Verdict::Unresolved(code),
                "exit {code} is not a verdict the judge delivered"
            );
        }
        // A signal reports no code at all, and "said nothing" is unresolved.
        assert_eq!(Verdict::of(None), Verdict::Unresolved(SIGNALLED));
    }

    #[test]
    fn only_a_clean_verdict_registers_nothing() {
        assert!(!Verdict::Clean.registers());
        assert!(Verdict::Raised.registers());
        assert!(Verdict::Unresolved(1).registers());
        assert!(Verdict::Unresolved(SIGNALLED).registers());
    }

    #[test]
    fn a_judge_row_with_no_table_or_no_run_cannot_resolve_a_command() {
        // Both spellings of "there is nothing to ask", and both name the row —
        // a config error has to point at the line that changes.
        for judge in [None, Some(&Judge {
            raw: Vec::new(),
            max_payload_bytes: None,
            run: None,
            model: None,
        })] {
            let err = argv("r", judge).expect_err("no run is a usage error");
            assert!(err.to_string().contains("rule r"), "{err}");
        }
        let blank = runner("   ", None);
        let err = argv("r", Some(&blank)).expect_err("a blank run is a usage error");
        assert!(err.to_string().contains("empty"), "{err}");
    }

    #[test]
    fn the_program_is_the_first_token_and_the_rest_are_arguments() {
        let judge = runner("judge-stub --strict -", None);
        assert_eq!(
            argv("r", Some(&judge)).unwrap(),
            ["judge-stub", "--strict", "-"]
        );
    }

    #[test]
    fn the_model_is_substituted_wherever_the_placeholder_appears() {
        let judge = runner("stub --model {{model}} --also={{model}}", Some("some-model"));
        assert_eq!(
            argv("r", Some(&judge)).unwrap(),
            ["stub", "--model", "some-model", "--also=some-model"]
        );
    }

    #[test]
    fn the_placeholder_with_no_model_refuses_rather_than_passing_itself_through() {
        // The failure this prevents is quiet: argv carrying a literal
        // `{{model}}` asks the operator's judge to evaluate against a model of
        // that name, and whatever comes back is a verdict about nothing.
        let judge = runner("stub --model {{model}}", None);
        let err = argv("r", Some(&judge)).expect_err("placeholder with no model refuses");
        assert!(err.to_string().contains(MODEL_PLACEHOLDER), "{err}");
    }

    #[test]
    fn a_model_with_no_placeholder_changes_no_token() {
        // `model` is opaque and positional-by-template: declaring one without
        // naming it in `run` must not smuggle an argument in.
        let judge = runner("stub --strict", Some("some-model"));
        assert_eq!(argv("r", Some(&judge)).unwrap(), ["stub", "--strict"]);
    }

    #[test]
    fn a_program_that_is_not_on_path_is_a_usage_error_naming_it() {
        let judge = runner("batten-judge-stub-that-does-not-exist", None);
        let argv = argv("r", Some(&judge)).unwrap();
        let err = invoke("r", &argv, b"{}").expect_err("an absent program refuses");
        assert!(
            err.to_string()
                .contains("batten-judge-stub-that-does-not-exist"),
            "the refusal must name the program: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_payload_crosses_on_stdin_and_the_exit_code_is_the_whole_verdict() {
        // Both halves of the contract in one run over a real process: `sh -c`
        // is the fixture here (not how a judge row is invoked — `invoke` never
        // uses a shell) because it can assert on stdin and choose an exit code.
        let payload = b"PAYLOAD-SENTINEL-crossed-on-stdin";
        let script = "read -r line; case \"$line\" in *PAYLOAD-SENTINEL*) exit 2;; *) exit 9;; esac";
        let argv = vec!["sh".to_owned(), "-c".to_owned(), script.to_owned()];
        assert_eq!(
            invoke("r", &argv, payload).unwrap(),
            Verdict::Raised,
            "the judge saw the payload on stdin, and its 2 is the verdict"
        );

        for (code, want) in [
            (0, Verdict::Clean),
            (2, Verdict::Raised),
            (1, Verdict::Unresolved(1)),
            (3, Verdict::Unresolved(3)),
        ] {
            let argv = vec!["sh".to_owned(), "-c".to_owned(), format!("exit {code}")];
            assert_eq!(invoke("r", &argv, payload).unwrap(), want);
        }
    }
}
