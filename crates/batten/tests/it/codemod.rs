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

/// A file whose only mention of the trait is in a string, a comment, and an
/// inline module's own `use`: none of them puts it in scope at the top.
const UNIMPORTED: &str = "\
//! Runs git.
#![allow(dead_code)]

use std::process::Command;

// use batten::stream::Streamed as _;
fn run() {
    let note = \"use batten::stream::Streamed as _;\";
    let _ = (note, Command::new(\"git\"));
}

mod inner {
    use batten::stream::Streamed as _;
}
";

const ITEM: &str = "use batten::stream::Streamed as _;";

/// Fails by: the import added inside a string, a comment or an inline module,
/// or anywhere but just before the first top-level `use`, or any other byte
/// changed.
#[test]
fn an_import_lands_before_the_first_top_level_use_and_nowhere_else() {
    let edited = codemod::ensure_use(UNIMPORTED, Edition::E2021, ITEM).unwrap();
    assert_eq!(
        edited,
        UNIMPORTED.replacen(
            "use std::process::Command;",
            "use batten::stream::Streamed as _;\nuse std::process::Command;",
            1
        )
    );
}

/// Fails by: a second copy added to a file that already imports the item, or
/// an import added to a file with no top-level `use` anywhere but before its
/// first item.
#[test]
fn an_import_is_added_once_and_a_file_without_imports_gets_it_first() {
    let once = codemod::ensure_use(UNIMPORTED, Edition::E2021, ITEM).unwrap();
    assert_eq!(
        codemod::ensure_use(&once, Edition::E2021, ITEM).unwrap(),
        once
    );
    let bare = "//! Docs.\n#![allow(dead_code)]\n\nfn run() {}\n";
    assert_eq!(
        codemod::ensure_use(bare, Edition::E2021, ITEM).unwrap(),
        "//! Docs.\n#![allow(dead_code)]\n\nuse batten::stream::Streamed as _;\nfn run() {}\n"
    );
}

/// Fails by: a source the parser rejects rewritten anyway.
#[test]
fn an_import_into_invalid_rust_is_could_not_look() {
    assert!(matches!(
        codemod::ensure_use("fn run( {}\n", Edition::E2021, ITEM),
        Err(CouldNotLook { .. })
    ));
}

/// Calls at the top level, inside a test module that imports its parent, and
/// inside a module with imports of its own; plus a decoy in a string.
const SCOPED: &str = "\
use std::process::Command;

fn run() -> Output {
    let note = \"x.streamed_output()\";
    Command::new(\"git\").streamed_output().unwrap()
}

mod repair {
    use std::path::Path;

    fn again() {
        let _ = Command::new(\"git\").streamed_output();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_here() {
        let _ = Command::new(\"git\").streamed_output();
    }
}
";

/// Fails by: the import put only at the file level (`repair` cannot see it,
/// and a test-only call leaves it unused in the library build), put at the
/// wrong indentation, put in a module with no call, or added twice.
#[test]
fn an_import_lands_in_every_module_that_calls_and_only_there() {
    let edited =
        codemod::import_for_calls(SCOPED, Edition::E2021, ITEM, "streamed_output").unwrap();
    assert_eq!(
        edited,
        SCOPED
            .replacen(
                "use std::process::Command;",
                "use batten::stream::Streamed as _;\nuse std::process::Command;",
                1
            )
            .replacen(
                "    use std::path::Path;",
                "    use batten::stream::Streamed as _;\n    use std::path::Path;",
                1
            )
            .replacen(
                "    use super::*;",
                "    use batten::stream::Streamed as _;\n    use super::*;",
                1
            )
    );
    assert_eq!(
        codemod::import_for_calls(&edited, Edition::E2021, ITEM, "streamed_output").unwrap(),
        edited,
        "once per module"
    );
    let test_only = "use std::process::Command;\n\n#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        let _ = Command::new(\"g\").streamed_output();\n    }\n}\n";
    assert_eq!(
        codemod::import_for_calls(test_only, Edition::E2021, ITEM, "streamed_output").unwrap(),
        test_only.replacen(
            "    #[test]",
            "    use batten::stream::Streamed as _;\n    #[test]",
            1
        ),
        "a call only in the test module imports only there"
    );
}

/// One call whose chain set a stream, one whose chain did not, and decoys: a
/// string, a comment, a stream set on a DIFFERENT chain, and a `let` that
/// breaks the chain.
const CHAINED: &str = "\
fn run() {
    let note = \"c.stdout(p).streamed_output()\"; // .stdout(p).streamed_output()
    let set = Command::new(\"a\").arg(\"x\").stdout(p).streamed_output();
    let plain = Command::new(\"b\").arg(\"y\").streamed_output();
    let other = Command::new(\"c\").stdout(p);
    let broken = other.streamed_output();
}
";

/// Fails by: a chain's methods misread (a call rewritten whose chain set no
/// stream, or one that did left alone), the chain's names handed in the wrong
/// order, a decoy rewritten, or any byte beyond the call's name and arguments
/// changed.
#[test]
fn a_call_is_rewritten_by_what_its_own_chain_called() {
    let seen = std::cell::RefCell::new(Vec::new());
    let rewrite = |chain: &[String]| {
        seen.borrow_mut().push(chain.to_vec());
        chain
            .iter()
            .any(|called| called == "stdout")
            .then(|| String::from("kept(Keep::STDOUT)"))
    };
    let edited =
        codemod::rewrite_calls_by_chain(CHAINED, Edition::E2021, "streamed_output", &rewrite)
            .unwrap();
    assert_eq!(
        edited,
        CHAINED.replacen(
            ".stdout(p).streamed_output();\n    let plain",
            ".stdout(p).kept(Keep::STDOUT);\n    let plain",
            1
        )
    );
    assert_eq!(
        *seen.borrow(),
        vec![
            vec![String::from("arg"), String::from("stdout")],
            vec![String::from("arg")],
            Vec::<String>::new(),
        ],
        "each call's own chain, in call order, and nothing across a `let`"
    );
}

/// Fails by: a doc line, a string, or a lint sharing the prefix counted as an
/// escape; a list naming the lint twice counted twice; an `allow`, an inner
/// attribute, or an escape among other lints missed; or another attribute
/// (`cfg`) counted. Built to break a text count: the decoys come first.
#[test]
fn lint_escapes_counts_the_attributes_that_name_the_lint_and_nothing_else() {
    let source = "\
//! Names clippy::disallowed_types in prose.
#![allow(clippy::disallowed_types)]
/// `#[expect(clippy::disallowed_types)]` in a doc line.
const S: &str = \"#[expect(clippy::disallowed_types)]\";
#[expect(clippy::disallowed_types_x)]
fn prefix() {}
#[expect(
    clippy::disallowed_types,
    reason = \"stays: one\"
)]
fn one() {}
#[allow(clippy::pedantic, clippy :: disallowed_types, clippy::disallowed_types)]
fn two() {}
#[cfg(clippy::disallowed_types)]
fn not_an_escape() {}
";
    assert_eq!(
        codemod::lint_escapes(source, Edition::E2024, "clippy::disallowed_types"),
        3,
        "the inner allow, `one` and `two`"
    );
    assert_eq!(
        codemod::lint_escapes(source, Edition::E2024, "clippy::disallowed_types_x"),
        1
    );
}
