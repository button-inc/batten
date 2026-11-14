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

/// Fails by: the refusal rendered as nothing, so the reader learns no count.
#[test]
fn could_not_look_renders_its_count_and_never_the_messages() {
    assert_eq!(
        CouldNotLook { errors: 3 }.to_string(),
        "the source does not parse (3 error(s)), so no rewrite was attempted"
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

/// CLOUD-2692: a call through a named path is redirected, arguments and every
/// other byte kept, while the same name in a `use`, a comment, a string, a
/// longer path or a method call is left alone.
#[test]
fn a_named_call_path_is_redirected_and_nothing_else() {
    const SOURCE: &str = r#"use std::fs::read_to_string;
// fs::read_to_string(a) in a comment
fn f(p: &str) -> String {
    let _s = "fs::read_to_string(x)";
    let _l = fs::read_to_string_lossy(p);
    let _m = reader.read_to_string(&mut buf);
    let a = fs::read_to_string(p).unwrap();
    let b = std::fs::read_to_string( p ).unwrap();
    assert_eq!(std::fs::read_to_string(p).unwrap(), "in a macro");
    assert!(x::fs::read_to_string(p).is_ok(), "fs::read_to_string(y)");
    a + &b
}
"#;
    let edited = codemod::redirect_calls(
        SOURCE,
        Edition::E2021,
        &["fs::read_to_string", "std::fs::read_to_string"],
        "crate::io::read_to_string",
    )
    .unwrap();
    assert!(
        edited.contains("let a = crate::io::read_to_string(p).unwrap();"),
        "{edited}"
    );
    assert!(
        edited.contains("let b = crate::io::read_to_string( p ).unwrap();"),
        "{edited}"
    );
    // Inside a macro's arguments too, and only the path's own bytes change.
    assert!(
        edited.contains("assert_eq!(crate::io::read_to_string(p).unwrap(), \"in a macro\");"),
        "{edited}"
    );
    for kept in [
        "x::fs::read_to_string(p)",
        "\"fs::read_to_string(y)\"",
        "use std::fs::read_to_string;",
        "// fs::read_to_string(a) in a comment",
        "\"fs::read_to_string(x)\"",
        "fs::read_to_string_lossy(p)",
        "reader.read_to_string(&mut buf)",
    ] {
        assert!(edited.contains(kept), "{kept} kept: {edited}");
    }
    // Nothing to redirect is byte-identical.
    let none = "fn g() {}\n";
    assert_eq!(
        codemod::redirect_calls(none, Edition::E2021, &["fs::read"], "crate::io::read").unwrap(),
        none
    );
}
