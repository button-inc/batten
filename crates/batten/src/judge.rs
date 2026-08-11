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
//! ## What a withheld span leaves behind
//!
//! A pointer and a hash, never nothing. The hash ([`crate::identity::
//! judge_fingerprint`]) lets a caller reference content it did not send — two
//! findings over identical withheld bytes are visibly the same content — without
//! the bytes leaving. It reuses the one length-prefixed construction rather than
//! minting a second hash of the same bytes.
//!
//! ## What this module does not do
//!
//! It performs no egress and spawns nothing: it is config types plus a pure
//! function, so a local model stays available by construction and there is no
//! network path here to review. Enforcement of the config half rides `config
//! lint`'s landed `read` row — see [`crate::lint`] for the opt-in smell.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

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
    /// What happens to a span the `protected` set covers.
    ///
    /// **Absent is not a default here, it is an unanswered question**, and
    /// `config lint` reports it as one whenever `protected` is non-empty
    /// (`judge-over-protected-unstated`). Payload construction still treats
    /// absent as [`OverProtected::Pointer`] — fail-closed — so the unanswered
    /// case is safe *and* visible rather than either alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub over_protected: Option<OverProtected>,
}

/// What a protected span may become in a payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum OverProtected {
    /// A pointer and a hash only. The bytes never leave.
    Pointer,
    /// Protected spans may also use the classes [`Judge::raw`] admits.
    ///
    /// The loud spelling of "yes, send my protected content to a model", which
    /// is exactly how loud that decision should have to be.
    Raw,
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

/// What a judge model call may carry.
///
/// Byte-identical for identical input: entries stay in the caller's order and no
/// field derives from the clock, the environment, or where the repository lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Payload {
    /// The entries, in the order the caller supplied them.
    pub entries: Vec<PayloadEntry>,
    /// How many entries carry content.
    pub sent: usize,
    /// How many were reduced to a pointer and a hash.
    pub withheld: usize,
}

/// Build the payload for `spans` under `protected` and `judge`.
///
/// A pure function of its three inputs — no I/O, no clock, no environment —
/// which is what lets the boundary be tested exhaustively rather than observed.
///
/// An absent `[judge]` is the same as a `[judge]` that admits nothing: pointers
/// and hashes only.
#[must_use]
pub fn build(spans: &[Span], protected: &PathSet, judge: Option<&Judge>) -> Payload {
    let (raw, over_protected) = judge.map_or((&[][..], OverProtected::Pointer), |judge| {
        (
            judge.raw.as_slice(),
            // Absent resolves to the withholding reading. `config lint` is what
            // makes the omission visible; the value here is what makes it safe.
            judge.over_protected.unwrap_or(OverProtected::Pointer),
        )
    });

    let mut entries = Vec::with_capacity(spans.len());
    let mut sent = 0;
    for span in spans {
        let attribution = span.attribution(protected);
        // Two independent gates, and both must pass. The class gate asks "may
        // this kind of content ever cross"; the protection gate asks "may THIS
        // span use that permission". Collapsing them would let one opt-in imply
        // the other.
        let class_admitted = raw.contains(&span.class);
        let protection_admits = !attribution.is_protected() || over_protected == OverProtected::Raw;
        let admitted = class_admitted && protection_admits;

        if admitted {
            sent += 1;
        }
        entries.push(PayloadEntry {
            rule: span.rule.clone(),
            pointer: pointer_of(span),
            class: span.class.as_str(),
            attribution,
            hash: identity::judge_fingerprint(span.class.as_str(), &span.bytes).to_hex(),
            // `from_utf8_lossy`: a payload is a model call, so it must be text.
            // Lossy rather than a refusal because the alternative — dropping a
            // span config explicitly admitted — would be a silent narrowing, and
            // the hash above still identifies the exact original bytes.
            text: admitted.then(|| String::from_utf8_lossy(&span.bytes).into_owned()),
        });
    }

    Payload {
        withheld: entries.len() - sent,
        entries,
        sent,
    }
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

    fn protected_set() -> PathSet {
        PathSet::includes("protected", &["secrets/**".to_owned()]).unwrap()
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
    /// payload for the protected bytes.
    fn carries(payload: &Payload, needle: &[u8]) -> bool {
        let json = serde_json::to_vec(payload).expect("the payload serializes");
        json.windows(needle.len()).any(|window| window == needle)
    }

    #[test]
    fn a_protected_span_is_a_pointer_and_a_hash_and_its_bytes_do_not_appear() {
        let spans = [span(
            Some("secrets/prod.env"),
            PayloadClass::SpanText,
            SECRET,
        )];
        // Even with the class admitted raw: the class gate passing is not the
        // protection gate passing.
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            over_protected: None,
        };
        let payload = build(&spans, &protected_set(), Some(&judge));

        assert_eq!(payload.sent, 0);
        assert_eq!(payload.withheld, 1);
        let entry = &payload.entries[0];
        assert_eq!(entry.attribution, Attribution::Protected);
        assert_eq!(entry.pointer.as_deref(), Some("secrets/prod.env:7"));
        assert_eq!(
            entry.hash.len(),
            64,
            "a withheld entry still identifies itself"
        );
        assert!(entry.text.is_none());
        assert!(
            !carries(&payload, SECRET),
            "no protected byte may appear in the payload"
        );
    }

    #[test]
    fn a_span_with_no_provenance_is_withheld_even_though_no_glob_matched_it() {
        // The fail-closed half. Nothing marked this span protected; nothing
        // could show it was safe either, and that resolves to withheld.
        let spans = [span(None, PayloadClass::SpanText, SECRET)];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            over_protected: Some(OverProtected::Pointer),
        };
        let payload = build(&spans, &PathSet::empty(), Some(&judge));

        assert_eq!(payload.entries[0].attribution, Attribution::NoProvenance);
        assert!(
            payload.entries[0].pointer.is_none(),
            "there is nothing to point at"
        );
        assert!(payload.entries[0].text.is_none());
        assert!(!carries(&payload, SECRET));
    }

    #[test]
    fn the_raw_opt_in_admits_exactly_the_named_class_and_nothing_else() {
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"the span"),
            span(Some("src/b.rs"), PayloadClass::FileText, b"the whole file"),
        ];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            over_protected: None,
        };
        let payload = build(&spans, &protected_set(), Some(&judge));

        assert_eq!(payload.sent, 1);
        assert_eq!(payload.entries[0].text.as_deref(), Some("the span"));
        assert!(
            payload.entries[1].text.is_none(),
            "a class the config did not name does not ride in on one it did"
        );
        assert!(!carries(&payload, b"the whole file"));
    }

    #[test]
    fn nothing_crosses_by_default() {
        let spans = [span(Some("src/a.rs"), PayloadClass::SpanText, b"the span")];
        for judge in [
            None,
            Some(Judge {
                raw: Vec::new(),
                over_protected: None,
            }),
        ] {
            let payload = build(&spans, &protected_set(), judge.as_ref());
            assert_eq!(payload.sent, 0, "an unconfigured judge sends no content");
            assert_eq!(payload.entries[0].attribution, Attribution::Unprotected);
            assert!(!carries(&payload, b"the span"));
        }
    }

    #[test]
    fn the_loud_opt_in_is_what_lets_protected_bytes_cross() {
        // The escape hatch exists and is reachable — otherwise the tests above
        // would pass over a boundary that simply never sends anything, which is
        // a different (and untested) design.
        let spans = [span(
            Some("secrets/prod.env"),
            PayloadClass::SpanText,
            SECRET,
        )];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            over_protected: Some(OverProtected::Raw),
        };
        let payload = build(&spans, &protected_set(), Some(&judge));

        assert_eq!(payload.sent, 1);
        assert!(
            carries(&payload, SECRET),
            "the loud opt-in must actually work"
        );
    }

    #[test]
    fn two_builds_over_the_same_input_are_byte_identical() {
        let spans = [
            span(Some("secrets/prod.env"), PayloadClass::SpanText, SECRET),
            span(None, PayloadClass::FileText, b"anonymous"),
            span(Some("src/a.rs"), PayloadClass::SpanText, b"ordinary"),
        ];
        let judge = Judge {
            raw: vec![PayloadClass::SpanText],
            over_protected: Some(OverProtected::Pointer),
        };
        let first = serde_json::to_vec(&build(&spans, &protected_set(), Some(&judge))).unwrap();
        let second = serde_json::to_vec(&build(&spans, &protected_set(), Some(&judge))).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_same_bytes_under_two_classes_are_two_identities() {
        // A hash stands for what was withheld, and "this span" and "this whole
        // file" are different claims even when the bytes agree.
        let spans = [
            span(Some("src/a.rs"), PayloadClass::SpanText, b"same"),
            span(Some("src/a.rs"), PayloadClass::FileText, b"same"),
        ];
        let payload = build(&spans, &protected_set(), None);
        assert_ne!(payload.entries[0].hash, payload.entries[1].hash);
    }

    #[test]
    fn every_class_has_a_token_and_they_are_distinct() {
        let tokens: Vec<&str> = PayloadClass::ALL.iter().map(|c| c.as_str()).collect();
        let mut unique = tokens.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(tokens.len(), unique.len(), "class tokens must be distinct");
    }
}
