//! "byte-perfect" is a reserved word, and this is what reserves it (CLOUD-917).
//!
//! [`batten::capture::Fidelity`] carries five values and exactly two of them may
//! be described as a faithful reproduction of the bytes a host framed. The other
//! three each fail differently: a decoded member is exact for what it decoded and
//! renormalizes key order, escaping and whitespace on the way back out; a prefix
//! makes no completeness claim at all; and an unavailable surface holds nothing.
//!
//! Without a mechanism this is a sentence in a doc comment, which is feedforward
//! only. The rule the issue states is that **no doc comment, output line, record
//! field or test name** may describe a reserialized decoded value that way — so
//! the gate reads the module's own prose and the type's own rendering, and
//! compares both against the one authority, `Fidelity::is_byte_perfect`.
//!
//! ## Why the sources are read with `include_str!`
//!
//! Compile-time, so there is no runtime path to resolve and no absolute path in a
//! failure message (non-negotiable rule 4, and `doctor.rs`'s
//! `a_reason_id_never_carries_a_path` for the same reason). It also means a
//! rename of either file is a compile error here rather than a scan that quietly
//! finds nothing — the `mise-tasks/` no-extension defect
//! (`.claude/rules/scanning.md`) in a different costume.

/// The term itself, spelled once so the scan cannot drift from the rule.
const RESERVED: &str = "byte-perfect";

/// The two values that may carry it, by token.
const ADMITTED: &[&str] = &["LexicalBytes", "SpillFile"];

/// The three that may not.
const REFUSED: &[&str] = &["DecodedContent", "Prefix", "Unavailable"];

const CAPTURE_SRC: &str = include_str!("../../src/capture.rs");
const HOOK_SRC: &str = include_str!("../../src/hook.rs");

/// The doc paragraphs of a source file.
///
/// A paragraph rather than a line, because the claim and the value it is about
/// are routinely on different lines of one comment — scanning line by line would
/// pass a comment that says "byte-perfect" two lines above the value it means.
///
/// **A blank doc line ends a paragraph**, and getting that wrong is what made
/// the first version of this scan unusable: treating a whole doc BLOCK as one
/// paragraph means a type whose docs legitimately discuss all five values can
/// never mention the term at all, so the only way to pass is to stop explaining
/// the rule. A paragraph is what a reader sees as one, and the reserved word
/// binds to the claim in front of them.
fn doc_paragraphs(src: &str) -> Vec<String> {
    let mut paragraphs = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut flush = |current: &mut Vec<&str>| {
        if !current.is_empty() {
            paragraphs.push(current.join(" "));
            current.clear();
        }
    };
    for line in src.lines() {
        let trimmed = line.trim_start();
        let body = trimmed
            .strip_prefix("///")
            .or_else(|| trimmed.strip_prefix("//!"));
        match body {
            // A doc line with nothing on it is the paragraph break a reader sees.
            Some(text) if text.trim().is_empty() => flush(&mut current),
            Some(text) => current.push(text.trim()),
            None => flush(&mut current),
        }
    }
    flush(&mut current);
    paragraphs
}

#[test]
fn only_a_lexical_or_spill_fidelity_is_ever_called_byte_perfect() {
    // Half one: the prose. Every doc paragraph that uses the reserved term must
    // name one of the two values it is true of, and must NOT name any of the
    // three it is false of.
    //
    // A NEGATED mention counts as a mention, deliberately: "not byte-perfect"
    // beside `DecodedContent` reads correctly to a human and still puts the
    // phrase one careless edit away from being a claim. So the refused values
    // avoid the hyphenated term entirely and say what they ARE instead — which
    // is why `Fidelity`'s own variant docs are worded the way they are.
    for (file, src) in [("capture.rs", CAPTURE_SRC), ("hook.rs", HOOK_SRC)] {
        for paragraph in doc_paragraphs(src) {
            if !paragraph.contains(RESERVED) {
                continue;
            }
            // This module's own header states the rule and necessarily names
            // every value while doing so; it is the one paragraph exempt, and it
            // is exempt by being in a different file from the two scanned.
            let names_admitted = ADMITTED.iter().any(|value| paragraph.contains(value));
            let named_refused: Vec<&&str> = REFUSED
                .iter()
                .filter(|value| paragraph.contains(**value))
                .collect();
            assert!(
                names_admitted,
                "{file}: a paragraph uses {RESERVED:?} without naming a value it \
                 is true of ({ADMITTED:?})"
            );
            assert!(
                named_refused.is_empty(),
                "{file}: a paragraph uses {RESERVED:?} beside {named_refused:?}, \
                 which cannot be described that way — state what the value IS \
                 rather than what it is not"
            );
        }
    }
}

#[test]
fn the_rendered_fidelity_note_carries_the_claim_exactly_where_the_type_does() {
    // Half two: the rendering, in both directions, so the claim cannot drift
    // out of the output while staying in the type or vice versa.
    for fidelity in batten::capture::Fidelity::ALL {
        let note = fidelity.note();
        assert_eq!(
            note.contains(RESERVED),
            fidelity.is_byte_perfect(),
            "{}: the rendered note and `is_byte_perfect` disagree about the \
             reserved word",
            fidelity.as_str()
        );
    }
}

#[test]
fn no_fidelity_token_or_note_carries_a_path() {
    // §6 and rule 4 together, the sibling of `doctor.rs`'s
    // `a_reason_id_never_carries_a_path`: these strings reach a byte-stable
    // record and a `doctor` row, where an absolute path would differ per machine
    // and leak disk layout.
    for fidelity in batten::capture::Fidelity::ALL {
        assert!(
            !fidelity.as_str().contains('/'),
            "{} looks like a path",
            fidelity.as_str()
        );
        assert!(
            !fidelity.note().contains('/'),
            "{}'s note looks like a path",
            fidelity.as_str()
        );
    }
}
