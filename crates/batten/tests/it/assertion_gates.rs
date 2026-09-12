//! A comment asserting a checkable property of the tree carries the gate that
//! checks it (CLOUD-1622 seam 4, non-negotiable rule 2).
//!
//! # The defect this closes
//!
//! Doc comments in this crate carry CONFORMANCE CLAIMS as well as doctrine, and
//! the two read identically. *"Which files carry a repository's contract is that
//! repository's business"* is doctrine — it states a rule and cannot go stale.
//! *"a grep of `crates/batten` for any of them returns nothing"* is a claim about
//! the tree AS IT IS, and nothing re-ran it.
//!
//! Measured on this branch: six such claims stood in `config.rs`, and the tracker
//! ones were FALSE — `get_issue`, `issue-read` and `updatedAt` appear throughout
//! `crates/batten/src`, one of the hits being a comment restating the same claim.
//! A reader auditing rule 1 would have read the assertion, believed the grep had
//! been run, and moved on. That is worse than no comment: it is a green light
//! nobody lit.
//!
//! # Why a marker rather than re-deriving the claim
//!
//! The gate cannot check the claims themselves — they are arbitrary properties of
//! the tree, and a scanner that tried to evaluate English would be the model
//! verdict non-negotiable rule 3 refuses. What it CAN decide is whether a claim
//! names something runnable, which is the same discipline `config.rs` already
//! applies to a `[[recorder]]` naming an undeclared program: the claim must point
//! at a task or a test THAT EXISTS.
//!
//! So the rule is: assert and cite, or state the doctrine and make no claim.
//!
//! # Why "conformance" and not the obvious word
//!
//! The obvious word is a consumer identifier, and `batten.toml`'s `source name
//! other` row forbids it anywhere under `crates/**`. This file spelled it four
//! times in its first draft and the gate refused the commit — which is the file's
//! own subject arriving one level up, and worth the line so nobody "corrects" the
//! vocabulary back. The phrases this module hunts are assembled at runtime for
//! the same reason; the prose had not been given the same care.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::{Path, PathBuf};

use crate::common;

/// The phrases that turn a comment from doctrine into a claim about the tree.
///
/// **Deliberately narrow, and narrow in the honest direction.** Each is a
/// conformance report — a statement that a SCAN was run and came back clean. A
/// wider net would catch doctrine and be switched off, which is the failure mode
/// a gate over prose has: measured, the first draft of this took the phrases
/// alone and reported twenty sites, of which most were ordinary prose about a
/// FUNCTION returning nothing. That gate would have been deleted, not obeyed.
///
/// So a block is a claim only when it names the scan as well as the result —
/// [`scan_word`] and one of these together. That is the shape non-negotiable rule 1
/// is itself written in, which is why it is the shape the claims copy.
///
/// Assembled at runtime for `the_engine_names_no_consumer_of_its_own`'s reason:
/// spelled as literals, this file's own corpus would carry every shape it hunts
/// and the module documenting the rule would be its own first violation.
fn claim_phrases() -> Vec<String> {
    [
        ("returns", "nothing"),
        ("return", "zero hits"),
        ("returns", "zero hits"),
        ("comes back", "clean"),
    ]
    .into_iter()
    .map(|(head, tail)| format!("{head} {tail}"))
    .collect()
}

/// The word that makes a clean result a claim about the TREE rather than about a
/// function's return type.
fn scan_word() -> String {
    format!("{}{}", "gr", "ep")
}

/// The marker a claim carries to name the gate behind it.
fn marker() -> String {
    format!("{}-{}:", "verified", "by")
}

/// Every `.rs` under the engine's source root.
fn engine_sources() -> Vec<PathBuf> {
    let root = common::at_root("crates/batten/src");
    let mut found = Vec::new();
    walk(&root, &mut found);
    found.sort();
    found
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

/// Every comment block in `text` carrying a claim phrase and no marker, as
/// `path:line` pointers (non-negotiable rule 4: a pointer, never the content).
///
/// A BLOCK rather than a line, because the marker will not sit on the same line
/// as the claim — a claim runs to a sentence and the citation follows it. The
/// block is the run of contiguous comment lines the claim sits in, which is the
/// unit a reader takes as one statement.
fn ungated_claims(path: &Path, text: &str, phrases: &[String], marker: &str) -> Vec<String> {
    let scan = scan_word();
    let lines: Vec<&str> = text.lines().collect();
    let is_comment = |line: &str| {
        let trimmed = line.trim_start();
        trimmed.starts_with("//") || trimmed.starts_with("/*") || trimmed.starts_with('*')
    };

    let mut found = Vec::new();
    let mut index = 0;
    while index < lines.len() {
        if !is_comment(lines[index]) {
            index += 1;
            continue;
        }
        let start = index;
        while index < lines.len() && is_comment(lines[index]) {
            index += 1;
        }
        let block = lines[start..index].join("\n").to_lowercase();
        // BOTH HALVES, and that conjunction is the whole discriminator: a clean
        // result alone is ordinary prose about a function, and the scan word alone
        // is doctrine describing the rule. Together they are a report.
        let claims =
            block.contains(&scan) && phrases.iter().any(|phrase| block.contains(phrase.as_str()));
        if claims && !block.contains(&marker.to_lowercase()) {
            found.push(format!("{}:{}", path.display(), start + 1));
        }
    }
    found
}

/// **The anti-vacuity half, and it comes first because the case below asserts an
/// ABSENCE.**
///
/// An absence passes for free if the scan could never have found anything — an
/// empty corpus, a misassembled phrase, a block splitter that never groups two
/// lines. Each direction is checked separately, because they fail independently.
#[test]
fn the_assertion_scan_would_find_an_ungated_claim() {
    let phrases = claim_phrases();
    let marker = marker();
    assert!(
        !engine_sources().is_empty(),
        "an empty corpus makes the absence below vacuous"
    );

    for phrase in &phrases {
        let planted = format!("/// A grep for the thing {phrase} today.\npub fn f() {{}}\n");
        assert_eq!(
            ungated_claims(Path::new("planted.rs"), &planted, &phrases, &marker).len(),
            1,
            "the scan must find an ungated `{phrase}` when it IS there, or its \
             absence below says nothing"
        );
    }

    // AND THE MARKER MUST ACTUALLY EXEMPT, or the rule is unsatisfiable and the
    // only way to a green tree is deleting the doctrine with the claim.
    let cited = format!(
        "/// A grep for the thing {} today.\n/// {} a_task\npub fn f() {{}}\n",
        phrases[0], marker
    );
    assert!(
        ungated_claims(Path::new("cited.rs"), &cited, &phrases, &marker).is_empty(),
        "a claim that names its gate is exactly what this rule asks for"
    );

    // AND THE MARKER MUST NOT REACH ACROSS BLOCKS. A citation in a neighbouring
    // comment is not a citation for this claim, and a splitter that merged the
    // file into one block would exempt every claim in it the moment any one of
    // them was cited — the most likely way this gate would go quiet.
    let elsewhere = format!(
        "/// {} a_task\npub fn cited() {{}}\n\n/// A grep for the thing {} today.\npub fn f() {{}}\n",
        marker, phrases[0]
    );
    assert_eq!(
        ungated_claims(Path::new("apart.rs"), &elsewhere, &phrases, &marker).len(),
        1,
        "a marker in another block must not exempt this one"
    );
}

/// **Every conformance claim in the engine names the gate that checks it.**
///
/// Fails by: writing a comment that reports a grep came back clean without
/// naming what re-runs it. The remedy is one of two, and both are fine — cite
/// the task or test, or state the doctrine and drop the claim. What is not fine
/// is the third thing, which is what this closes: a reader told the check was
/// run, by a comment that is the only record it ever was.
#[test]
fn every_conformance_claim_names_its_gate() {
    let phrases = claim_phrases();
    let marker = marker();
    let mut found = Vec::new();
    for path in engine_sources() {
        let text = fs::read_to_string(&path).expect("readable source");
        found.extend(ungated_claims(&path, &text, &phrases, &marker));
    }
    assert!(
        found.is_empty(),
        "these comments report a check as having been run and name nothing that \
         re-runs it, so they go stale silently and read as a green light nobody \
         lit. Cite the gate with a `{marker}` marker, or state the doctrine and \
         make no claim (non-negotiable rule 2):\n{}",
        found.join("\n")
    );
}
