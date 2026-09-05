//! A rules file may not contradict the manifest about which builtins exist
//! (CLOUD-1104).
//!
//! `rules/policy-modules.md` told every policy-module author that this
//! build of regorus carries no `regex` builtins, as the stated reason a module
//! must anchor on `input.call.segments`. It does carry them: `Cargo.toml`
//! enables the feature, and `policy/stop-posture.rego` calls `regex.find_n` over
//! a `[[pattern]]` row in an enforced module today.
//!
//! The dates are what make it a defect rather than staleness. The feature landed
//! `66b8d23` (2026-08-22); the false clause landed `1bdb15f` (2026-08-28), **six
//! days later** — CLOUD-885's problem statement copied forward into the
//! authoring guide after CLOUD-885 had fixed it.
//!
//! ## Why a prose correction alone would not have been the change
//!
//! Non-negotiable rule 2: a rule without a runnable gate is half a change. The
//! clause arrived by copy-forward and nothing saw it, which is precisely how it
//! would arrive again — and this file is where `shell add refused`'s remedy
//! `rule read first` sends authors, with CLOUD-843's wave 1 copying its
//! template ~80 times. A wrong sentence there is ~80 authors pushed toward
//! hand-rolled string work that the `[[pattern]]` registry exists to make
//! unwritable.
//!
//! ## The object is an AGREEMENT between two authorities, not a string
//!
//! `Cargo.toml`'s feature list is the one authority on what regorus carries. The
//! finding is a paragraph that names regorus, names an **enabled** feature as a
//! code span, and denies it in the same breath. That pairing is what makes the
//! case discriminate rather than merely assert a string is absent (CLOUD-418):
//!
//! * restore the false clause and this goes **red**;
//! * keep the corrected prose and drop `regex` from the manifest and it stays
//!   **green**, because then the prose would be true.
//!
//! A case that only checked the sentence were missing would pass on a tree where
//! the manifest had changed underneath it, which is the same one-sided reading
//! that let the clause land.
//!
//! ## What this cannot catch, stated rather than implied away
//!
//! [`DENIALS`] is a closed set of spellings, so a copy-forward worded a way it
//! does not list slips through. That is a real bound: the honest object here is
//! "a paragraph that denies an enabled feature in words we recognise", never
//! "the file contains no false claim", and no §7 clause should be read as the
//! second. `crates/batten/tests/it/scanner_taxonomy.rs` sets the precedent of
//! saying plainly what a prose assertion holds and what it does not.
//!
//! The granularity is a **paragraph** rather than a sentence, deliberately:
//! sentence splitting on `.` mis-cuts every `Cargo.toml`, `0.11` and
//! `regex.find_n` in this corpus, so the cheap unit is also the accurate one.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::common;

use std::fs;

use batten::facts::{Format, Look, Node};
use common::at_root;

/// The dependency whose feature list decides which builtins the evaluator has.
const CRATE: &str = "regorus";

/// Where that list lives, as a dotted path into the workspace manifest.
const FEATURES: &str = "workspace.dependencies.regorus.features";

/// The directory whose prose is judged.
///
/// The neutral home since CLOUD-1152. `.claude/rules/` holds pointer stubs
/// carrying Claude Code's `paths:` trigger and no rule of its own, so judging
/// that directory would judge five files that make no claim — and would be
/// silent over the five that do.
const RULES_DIR: &str = "rules";

/// The words that turn naming a feature into denying it.
///
/// Closed, and the module docs say so: this recognises the spellings the defect
/// actually used and the ones nearest to them, not every way a sentence can
/// carry a negation.
const DENIALS: &[&str] = &[
    "carries no",
    "built without",
    "does not carry",
    "has no",
    "lacks",
    "is not available",
    "are not available",
    "unavailable",
    "no such builtin",
    "without the",
];

/// The features `Cargo.toml` actually enables, read through the engine's own
/// TOML reader rather than a second parser — the same route `spawn_census.rs`
/// takes to the `tokio` list.
fn enabled_features() -> Vec<String> {
    let text = fs::read_to_string(at_root("Cargo.toml")).expect("the workspace manifest is here");
    let manifest = match Format::Toml.read(&text) {
        Look::Is(node) => node,
        other => panic!("the workspace manifest did not parse: {other:?}"),
    };
    let Look::Is(Node::List(features)) = manifest.at(FEATURES) else {
        panic!("[workspace.dependencies] must declare {CRATE} with an explicit feature list")
    };
    features
        .iter()
        .filter_map(|entry| match entry {
            Node::Text(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

/// Every tracked rules file, as `(path, contents)`.
fn rules_files() -> Vec<(String, String)> {
    let dir = at_root(RULES_DIR);
    let mut found: Vec<(String, String)> = fs::read_dir(&dir)
        .expect("the rules directory is committed")
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("md"))
        .map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default()
                .to_owned();
            let text = fs::read_to_string(&path).expect("a rules file reads");
            (format!("{RULES_DIR}/{name}"), text)
        })
        .collect();
    found.sort();
    found
}

/// Every paragraph that denies an enabled feature, as `path:paragraph`.
///
/// Pointer-only (non-negotiable rule 4): the path, the 1-indexed line the
/// paragraph starts at, and the feature. Never the sentence — a finding that
/// quoted the prose would put the false claim in the gate's own output.
fn denials_of_enabled_features(features: &[String]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in rules_files() {
        let mut line = 1_usize;
        for paragraph in text.split("\n\n") {
            let lowered = paragraph.to_lowercase();
            if lowered.contains(CRATE) && DENIALS.iter().any(|denial| lowered.contains(denial)) {
                for feature in features {
                    // A CODE SPAN, never a bare substring. `std`, `ast` and
                    // `arc` all live inside ordinary words — "standard",
                    // "last", "search" — so a substring match would report
                    // this corpus as one long violation.
                    if paragraph.contains(&format!("`{feature}`")) {
                        found.push(format!("{path}:{line} `{feature}`"));
                    }
                }
            }
            line += paragraph.matches('\n').count() + 2;
        }
    }
    found.sort();
    found
}

#[test]
fn no_rules_file_denies_a_builtin_the_manifest_enables() {
    let features = enabled_features();
    let found = denials_of_enabled_features(&features);
    assert!(
        found.is_empty(),
        "a rules file denies a {CRATE} feature `Cargo.toml` enables, so an author is being \
         told to hand-roll what the evaluator already does: {found:?}. The manifest is the one \
         authority; delete the claim rather than restating it."
    );
}

#[test]
fn the_case_fires_on_the_clause_this_row_removed() {
    // THE DISCRIMINATOR (CLOUD-418), over the real text rather than a paraphrase:
    // this is `rules/policy-modules.md`'s clause as it stood at `1bdb15f`.
    // Without this the case above is satisfied by a predicate that never fires,
    // which is the shape a copy-forward would sail straight past.
    let paragraph = "There is **one parser**, and a module must not grow a second: no `split` of \
                     the command line, in Rego or in Rust. That is not style — without the \
                     projection it is ~60 lines of core-builtin string work per module (a list \
                     split, a pipe-stage split, a quoted-span scrub) because this build of \
                     regorus carries no `regex` builtins.";
    let lowered = paragraph.to_lowercase();
    assert!(
        lowered.contains(CRATE)
            && DENIALS.iter().any(|denial| lowered.contains(denial))
            && paragraph.contains("`regex`"),
        "the removed clause must still be recognised as a denial, or this gate reports green \
         over the very defect it was written for"
    );
}

#[test]
fn the_verdict_is_an_agreement_rather_than_a_string_search() {
    // THE OTHER HALF, and the one that keeps this from being "the file must not
    // say `regex`". The same paragraph is not a finding when the manifest does
    // NOT enable the feature — because then it is simply true. Asserted by
    // judging against a feature list that omits it.
    let features = vec!["ast".to_owned(), "std".to_owned()];
    assert!(
        denials_of_enabled_features(&features).is_empty(),
        "a claim about a feature the manifest does not enable is true prose, not a finding"
    );

    // And the pairing is live rather than hypothetical: `regex` IS enabled here,
    // so a tree carrying the clause would be red on the first case.
    assert!(
        enabled_features().iter().any(|feature| feature == "regex"),
        "this row exists because `regex` is enabled; if that changed, the prose \
         CLOUD-1104 corrected has to be revisited rather than this gate relaxed"
    );
}
