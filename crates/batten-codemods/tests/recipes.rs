//! Every saved recipe, on a fixture built to break a splicer, and idempotent
//! on its own output: a recipe run twice rewrites nothing the second time.

// Panicking on setup failure is the idiomatic way for a test to fail loudly.
#![allow(clippy::unwrap_used, clippy::expect_used)]

/// The original `gen` fixture: a string literal carrying `.gen()` ahead of the
/// real call, a doc comment, and a longer name.
const SRC: &str = "\
/// Draws a value. The retired API spelled this `gen`.
fn draw(rng: &mut impl Rng) -> u32 {
\tlet note = \"call .gen() here\";
        let span = rng.gen_range(0..10);
\tlet value: u32 = rng.gen(); // the one call to migrate
        value + span + note.len() as u32
}
";

/// A file with one real `.output()` and decoys of every near shape.
const CAPTURED: &str = "\
use std::process::Command;

fn run(ran: &Ran) -> usize {
    let note = \"call .output() here\"; // .wait_with_output() too
    let dir = ran.output_dir();
    let held = ran.output;
    let out = Command::new(\"git\").output().unwrap();
    note.len() + dir.len() + held.len() + out.stdout.len()
}
";

/// Fails by: a decoy rewritten (the string, the comment, a field, a longer
/// method), the trait not imported where the rename landed, or the recipe
/// rewriting its own output a second time.
#[test]
fn the_stream_recipe_moves_the_call_and_imports_its_trait_once() {
    let recipe = batten_codemods::named("stream-capture").expect("saved");
    let edited = (recipe.apply)(CAPTURED, "crate").unwrap();
    assert_eq!(
        edited,
        CAPTURED
            .replacen(
                "use std::process::Command;",
                "use crate::capture::Streamed as _;\nuse std::process::Command;",
                1
            )
            .replacen(
                "Command::new(\"git\").output()",
                "Command::new(\"git\").streamed_output()",
                1
            )
    );
    assert_eq!(
        (recipe.apply)(&edited, "crate").unwrap(),
        edited,
        "idempotent"
    );
}

/// A file carrying both parse spellings and every decoy a text splice gets
/// wrong: the call named in a string, a comment, a `use`, and a longer path.
const PARSES: &str = "\
use ra_ap_syntax::SourceFile;
// SourceFile::parse(x, e) is the old spelling
fn a(text: &str) {
    let s = \"SourceFile::parse(text, e)\";
    let one = SourceFile::parse(text, ra_ap_syntax::Edition::Edition2024);
    let two = ra_ap_syntax::SourceFile::parse(text, ra_ap_syntax::Edition::Edition2021);
    let longer = SourceFile::parse_with_errors(text);
}
";

/// Fails by: a decoy rewritten, either spelling missed, an edition argument
/// changed, or the recipe rewriting its own output a second time.
#[test]
fn the_parse_recipe_moves_both_spellings_and_keeps_each_edition() {
    let recipe = batten_codemods::named("one-rust-parse").expect("saved");
    let edited = (recipe.apply)(PARSES, "crate").unwrap();
    assert_eq!(
        edited,
        PARSES
            .replacen(
                "let one = SourceFile::parse(",
                "let one = batten_facts::source::rust_parse(",
                1
            )
            .replacen(
                "let two = ra_ap_syntax::SourceFile::parse(",
                "let two = batten_facts::source::rust_parse(",
                1
            )
    );
    assert_eq!(
        (recipe.apply)(&edited, "crate").unwrap(),
        edited,
        "idempotent"
    );
}

/// Fails by: a read redirected inside a string, a longer path, or a method
/// of the same name, or the recipe rewriting its own output again.
#[test]
fn the_fsio_recipe_redirects_reads_and_nothing_else() {
    let source = "\
fn read(p: &Path) -> String {
    let note = \"std::fs::read_to_string(p)\";
    let _ = x::fs::read(p);
    let _ = p.read_to_string();
    std::fs::read_to_string(p).unwrap() + note
}
";
    let recipe = batten_codemods::named("fsio-reads").expect("saved");
    let edited = (recipe.apply)(source, "crate").unwrap();
    assert_eq!(
        edited,
        source.replacen(
            "    std::fs::read_to_string(p).unwrap()",
            "    crate::fsio::read_to_string(p).unwrap()",
            1
        )
    );
    assert_eq!(
        (recipe.apply)(&edited, "crate").unwrap(),
        edited,
        "idempotent"
    );
}

/// Fails by: the rand recipe parsing under 2024, where `gen` is a keyword and
/// the source would be could-not-look, or touching the string decoy.
#[test]
fn the_rand_recipe_is_the_original_rename_under_its_own_edition() {
    let recipe = batten_codemods::named("rand-random").expect("saved");
    let edited = (recipe.apply)(SRC, "crate").unwrap();
    assert_eq!(edited, SRC.replacen("rng.gen()", "rng.random()", 1));
    assert_eq!(
        (recipe.apply)(&edited, "crate").unwrap(),
        edited,
        "idempotent"
    );
}

/// Fails by: a chain that set a stream left on the all-defaults call, a chain
/// that set none rewritten, the wrong stream named, or the recipe rewriting
/// its own output again.
#[test]
fn the_keep_recipe_names_exactly_the_streams_a_chain_set() {
    let source = "\
fn run() {
    let a = c().stdin(f).stderr(p).streamed_output();
    let b = c().arg(\"x\").streamed_output();
    let d = c().stdin(f).streamed_output();
    let e = c().stdout(o).streamed_output();
}
";
    let recipe = batten_codemods::named("stream-keep-set").expect("saved");
    let edited = (recipe.apply)(source, "batten").unwrap();
    let keeping = |stdin: bool, stdout: bool, stderr: bool| {
        format!(
            "streamed_output_keeping(batten::capture::Keep {{ stdin: {stdin}, stdout: {stdout}, stderr: {stderr} }})"
        )
    };
    // ONE STREAM ALONE IS ENOUGH: each of the three is its own reason to keep.
    assert_eq!(
        edited,
        source
            .replacen(
                ".stderr(p).streamed_output()",
                &format!(".stderr(p).{}", keeping(true, false, true)),
                1
            )
            .replacen(
                ".stdin(f).streamed_output()",
                &format!(".stdin(f).{}", keeping(true, false, false)),
                1
            )
            .replacen(
                ".stdout(o).streamed_output()",
                &format!(".stdout(o).{}", keeping(false, true, false)),
                1
            )
    );
    assert_eq!(
        (recipe.apply)(&edited, "batten").unwrap(),
        edited,
        "idempotent"
    );
}

/// Fails by: a moved item's path left on `stream`, a different item sharing
/// the prefix (`StreamedX`, `stream::pump`) moved too, or a use alias or a
/// struct literal's fields dropped.
#[test]
fn the_adapter_recipe_moves_exactly_the_three_items() {
    let source = "\
use batten::stream::Streamed as _;
use batten::stream::StreamedChild as _;
use batten::stream::pump;
fn run() {
    let k = batten::stream::Keep { stdin: true, ..batten::stream::Keep::NONE };
    let s = \"batten::stream::Keep\";
    let x = batten::stream::StreamedX;
}
";
    let recipe = batten_codemods::named("stream-adapter-exec").expect("saved");
    let edited = (recipe.apply)(source, "batten").unwrap();
    assert_eq!(
        edited,
        "\
use batten::capture::Streamed as _;
use batten::capture::StreamedChild as _;
use batten::stream::pump;
fn run() {
    let k = batten::capture::Keep { stdin: true, ..batten::capture::Keep::NONE };
    let s = \"batten::stream::Keep\";
    let x = batten::stream::StreamedX;
}
"
    );
    assert_eq!(
        (recipe.apply)(&edited, "batten").unwrap(),
        edited,
        "idempotent"
    );
}

/// `(path, text)` rows as the tree recipes take them.
fn tree(rows: &[(&str, &str)]) -> std::collections::BTreeMap<String, String> {
    rows.iter()
        .map(|(path, text)| ((*path).to_owned(), (*text).to_owned()))
        .collect()
}

/// Fails by: the tree recipe returning nothing, or a file it never split.
#[test]
fn the_split_recipe_writes_each_inline_module_to_its_own_file() {
    let recipe = batten_codemods::named_tree("split-inline-modules").expect("saved");
    let files = tree(&[(
        "src/check.rs",
        "pub mod a {\n    pub fn f() {}\n}\npub mod b {\n    pub fn g() {}\n}\n",
    )]);
    assert_eq!(
        (recipe.apply)(&files, &tree(&[])),
        tree(&[
            ("src/check.rs", "pub mod a;\npub mod b;\n"),
            ("src/check/a.rs", "pub fn f() {}\n"),
            ("src/check/b.rs", "pub fn g() {}\n"),
        ])
    );
}

/// Fails by: the trait not made in the package's own file, or a path out
/// that is no file of the tree it was given.
#[test]
fn the_extension_trait_recipe_changes_only_files_of_the_package() {
    let recipe = batten_codemods::named_tree("impl-to-extension-trait").expect("saved");
    let files = tree(&[
        ("crates/app/src/lib.rs", "mod model;\nmod rules;\n"),
        ("crates/app/src/model.rs", "pub struct Rule { pub x: u8 }\n"),
        (
            "crates/app/src/rules.rs",
            "use crate::model::Rule;\nimpl Rule {\n    pub fn twice(&self) -> u8 { self.x * 2 }\n}\n",
        ),
    ]);
    let manifests = tree(&[("crates/app/Cargo.toml", "[package]\nname = \"app\"\n")]);
    let changed = (recipe.apply)(&files, &manifests);
    assert!(
        changed["crates/app/src/rules.rs"].contains("pub trait RuleExt"),
        "{changed:?}"
    );
    for (path, text) in &changed {
        assert!(files.contains_key(path), "{path} is no file of the tree");
        assert_ne!(Some(text), files.get(path), "{path} unchanged");
    }
}
