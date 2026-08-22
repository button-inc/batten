//! A tree-scoped rule can carve a path class out of an otherwise broad glob
//! (CLOUD-883).
//!
//! # What was impossible, measured rather than argued
//!
//! `Rule::glob` was one inclusive pattern. A rule could say *these files* and
//! not *these files except those*, so a cheap broad rule and a precise narrow
//! one could not compose over one tree: the broad one always double-reported
//! what the narrow one owned. CLOUD-881 is the measured instance — a `forbid`
//! row over `**` reporting a legitimate dependency pin in `Cargo.toml`, because
//! deciding that needs the TOML table the line sits in, which is a structural
//! question a literal cannot ask.
//!
//! # The direction that matters
//!
//! `Selector`'s doc names it: *widening is the single direction a policy engine
//! may never drift*. Every case here is oriented on that. The selection is a
//! `PathSet`, whose exclude-beats-include rule is order-independent, so the
//! selected set is a subset of the glob's by construction — and the cases that
//! could go the other way (a `!` that reads as re-inclusion, a ratchet whose two
//! sides would disagree) are refused at LOAD, each shown red here.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use std::path::PathBuf;

use common::{Fixture, run, stdout};

/// A broad `forbid` row, optionally carving out the manifest.
fn broad(exclude: Option<&str>) -> String {
    let carve = exclude.map_or_else(String::new, |glob| {
        format!("exclude_paths = [\"{glob}\"]\n")
    });
    format!(
        "version = 1\n\
         \n\
         [[rule]]\n\
         id = \"no-appeal\"\n\
         kind = \"forbid\"\n\
         glob = \"**\"\n\
         pattern = \"blessed-by\"\n\
         severity = \"warn\"\n\
         scope = \"tree\"\n\
         no_fix_reason = \"say who decided, not who blessed it\"\n\
         {carve}"
    )
}

/// A tree carrying the phrase in prose AND in a manifest, which is the shape
/// CLOUD-881 hit: the row is right about the prose and wrong about the pin.
fn repo(name: &str, config: &str) -> PathBuf {
    Fixture::new(name)
        .config(config)
        .file("notes.md", "blessed-by the architect\n")
        .file("Cargo.toml", "[dependencies]\nblessed-by = \"1\"\n")
        .git()
        .base_commit()
        .build()
}

#[test]
fn without_the_exclusion_the_broad_row_reports_the_manifest() {
    // The RED half, and it is the state `main` is in: this is the finding
    // CLOUD-881 could not get rid of. Asserted rather than described, so the
    // case below is measured against something real.
    let dir = repo("glob-exclusion-before", &broad(None));
    let output = run(&dir, &["check"]);

    assert!(
        stdout(&output).contains("Cargo.toml"),
        "the broad row must reach the manifest without an exclusion: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("notes.md"),
        "and the prose, which is the half it is right about: {}",
        stdout(&output)
    );
}

#[test]
fn the_exclusion_carves_out_the_manifest_and_leaves_the_prose() {
    // The composition CLOUD-883 exists for: the broad row stops reporting the
    // path a better-suited rule owns, and keeps reporting everything else. Both
    // halves are asserted, because a rule that stopped reporting EVERYTHING
    // would also pass the first one.
    let dir = repo("glob-exclusion-after", &broad(Some("**/Cargo.toml")));
    let output = run(&dir, &["check"]);

    assert!(
        !stdout(&output).contains("Cargo.toml"),
        "the manifest is carved out: {}",
        stdout(&output)
    );
    assert!(
        stdout(&output).contains("notes.md"),
        "the prose is still judged — the exclusion narrows, it does not disable: {}",
        stdout(&output)
    );
}

#[test]
fn an_exclusion_that_matches_nothing_changes_nothing() {
    // Narrowing by zero. Stated because the opposite would be the quiet failure:
    // an exclusion the author misspelled must leave the rule exactly as broad as
    // it was, never silently wider or narrower.
    let dir = repo("glob-exclusion-inert", &broad(Some("**/nothing-here.txt")));
    let output = run(&dir, &["check"]);

    assert!(
        stdout(&output).contains("Cargo.toml"),
        "{}",
        stdout(&output)
    );
    assert!(stdout(&output).contains("notes.md"), "{}", stdout(&output));
}

#[test]
fn a_bang_prefixed_exclusion_is_refused_at_load() {
    // THE WIDENING ARM. This column is already the negative half, so a `!` here
    // is a double negative that reads as re-inclusion — the one direction that
    // would select MORE than the author wrote. Refused at load rather than
    // interpreted, because either reading of it is a guess about intent.
    let dir = repo("glob-exclusion-bang", &broad(Some("!**/Cargo.toml")));
    let output = run(&dir, &["check"]);

    assert_eq!(
        output.status.code(),
        Some(1),
        "a config fault, not a verdict"
    );
    assert!(
        common::stderr(&output).contains("widens"),
        "the refusal names the direction: {}",
        common::stderr(&output)
    );
}

#[test]
fn a_malformed_exclusion_is_refused_at_load() {
    // A glob that does not compile must name its row, never quietly select
    // nothing — the same reasoning `a_glob_that_does_not_compile_is_refused_where_it_is_named`
    // already applies to the include half.
    let dir = repo("glob-exclusion-malformed", &broad(Some("crates/[unclosed")));
    let output = run(&dir, &["check"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        common::stderr(&output).contains("no-appeal"),
        "the refusal names the row: {}",
        common::stderr(&output)
    );
}

#[test]
fn an_exclusion_with_no_glob_to_subtract_from_is_refused() {
    // It would narrow nothing while reading as a narrowing.
    let dir = Fixture::new("glob-exclusion-no-glob")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"call-shaped\"\n\
             kind = \"shape\"\n\
             pattern = \"git push --force\"\n\
             severity = \"deny\"\n\
             scope = \"mediated_call\"\n\
             no_fix_reason = \"push without the flag\"\n\
             exclude_paths = [\"**/Cargo.toml\"]\n",
        )
        .build();
    let output = run(&dir, &["check"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        common::stderr(&output).contains("narrow nothing"),
        "the refusal says why: {}",
        common::stderr(&output)
    );
}

#[test]
fn a_ratchet_may_not_carry_one() {
    // Its base-rev count globs on its own and cannot read this column, so the
    // two sides would select different sets — and the direction is CLOUD-328's:
    // a working side narrowed below its base can never rise above it, so the
    // gate cannot fail. A gate that cannot fail reads exactly like one passing.
    let dir = Fixture::new("glob-exclusion-ratchet")
        .config(
            "version = 1\n\
             \n\
             [[rule]]\n\
             id = \"no-more-bash\"\n\
             kind = \"ratchet\"\n\
             glob = \"**/*.sh\"\n\
             direction = \"non_increasing\"\n\
             severity = \"deny\"\n\
             scope = \"tree\"\n\
             no_fix_reason = \"retire one first\"\n\
             exclude_paths = [\"vendor/**\"]\n",
        )
        .git()
        .base_commit()
        .build();
    let output = run(&dir, &["check"]);

    assert_eq!(output.status.code(), Some(1));
    assert!(
        common::stderr(&output).contains("could not fail"),
        "the refusal names the consequence: {}",
        common::stderr(&output)
    );
}
