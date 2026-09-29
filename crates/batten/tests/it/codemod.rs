//! `codemod`'s contract: a rewrite changes the edited token and nothing else,
//! and a source the parser rejects is could-not-look (CLOUD-1580).
//!
//! # The fixture is built to break a splicer
//!
//! A string literal carrying `.gen()` comes BEFORE the real call, and a doc
//! comment names `gen`. A byte splice at the first textual match lands in the
//! string, so the declared `codemod-splices-bytes` mutation reddens
//! `a_rename_changes_only_the_edited_token`, while a tree edit touches only the
//! call. `gen_range`, a trailing comment on the edited line and mixed tab and
//! 8-space indentation are all there to be left alone.
//
// The obligations CLOUD-1580's Ready block binds. The rows themselves are swept
// from `crates/batten/src/codemod.rs`, the file they mutate:
// MUTANT codemod-splices-bytes|see `codemod::rename_method_calls`|a_rename_changes_only_the_edited_token
// MUTANT codemod-ignores-parse-errors|see `codemod::rename_method_calls`|invalid_rust_is_could_not_look

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use batten::codemod::{self, CouldNotLook, Edition};

const SRC: &str = "\
/// Draws a value. The retired API spelled this `gen`.
fn draw(rng: &mut impl Rng) -> u32 {
\tlet note = \"call .gen() here\";
        let span = rng.gen_range(0..10);
\tlet value: u32 = rng.gen(); // the one call to migrate
        value + span + note.len() as u32
}
";

#[test]
fn a_rename_changes_only_the_edited_token() {
    let edited = codemod::rename_method_calls(SRC, Edition::E2021, "gen", "random").unwrap();
    assert_eq!(
        edited,
        SRC.replacen("rng.gen()", "rng.random()", 1),
        "only the method call's own name may change",
    );
    assert!(
        edited.contains("\"call .gen() here\""),
        "the string literal is untouched"
    );
    assert!(
        edited.contains("rng.gen_range(0..10)"),
        "a longer name is not a match"
    );
    assert!(
        edited.contains("spelled this `gen`"),
        "the doc comment is untouched"
    );
    assert!(
        edited.contains("// the one call to migrate"),
        "the trailing comment survives"
    );
}

#[test]
fn invalid_rust_is_could_not_look() {
    let broken = "fn draw(rng: &mut R) -> u32 { rng.gen( }\n";
    let answer = codemod::rename_method_calls(broken, Edition::E2021, "gen", "random");
    assert!(
        matches!(answer, Err(CouldNotLook { errors }) if errors > 0),
        "a source the parser rejects is never rewritten, and never passed through as if it were clean: {answer:?}",
    );
}

#[test]
fn the_edition_is_an_input() {
    // `gen` is a keyword in 2024, so the same source is could-not-look there
    // and clean under 2021. That is why the edition has no default.
    assert!(codemod::rename_method_calls(SRC, Edition::E2024, "gen", "random").is_err());
    assert!(codemod::rename_method_calls(SRC, Edition::E2021, "gen", "random").is_ok());
}

#[test]
fn an_absent_method_changes_nothing() {
    let edited = codemod::rename_method_calls(SRC, Edition::E2021, "fill_bytes", "fill").unwrap();
    assert_eq!(edited, SRC);
}

#[test]
fn every_matching_call_is_renamed() {
    let src = "fn f(a: &mut R, b: &mut R) { a.gen(); b.gen(); }\n";
    let edited = codemod::rename_method_calls(src, Edition::E2021, "gen", "random").unwrap();
    assert_eq!(
        edited,
        "fn f(a: &mut R, b: &mut R) { a.random(); b.random(); }\n"
    );
}
