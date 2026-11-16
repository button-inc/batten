//! Named codemods: each migration this repository ran, kept as a recipe (#1276).
//!
//! A recipe is a migration already proven on this tree, written only in
//! `batten`'s codemod primitives ([`codemod::rename_method_calls`],
//! [`codemod::redirect_calls`], [`codemod::import_for_calls`],
//! [`codemod::rewrite_calls_by_chain`]). This crate is never
//! released: a recipe reaches the shipped binary only when a preset vendors it. It is kept rather than thrown away with its driver for
//! two reasons. A consumer making the same move runs it as one call, which is
//! what vendoring one into a preset will mean. And the tree it already migrated
//! is its regression test: run again, it rewrites nothing.
//!
//! `cargo run -p batten-codemods --example codemod -- <recipe>` runs one by name.

use batten::codemod::{self, CouldNotLook, Edition};

/// One named migration.
#[derive(Debug, Clone, Copy)]
pub struct Recipe {
    /// What the driver is asked for.
    pub name: &'static str,
    /// The move, in one line.
    pub summary: &'static str,
    /// The edition the files it rewrites parse under.
    pub edition: Edition,
    /// Path suffixes it never rewrites: a second compilation context, or the
    /// module that defines what it migrates to.
    pub skip: &'static [&'static str],
    /// The rewrite of one file. `base` is how that file names the crate the
    /// recipe migrates onto: `crate` inside it, its package name outside.
    pub apply: fn(source: &str, base: &str) -> Result<String, CouldNotLook>,
}

/// Every recipe, in the order they were first run.
pub const RECIPES: &[Recipe] = &[
    Recipe {
        name: "rand-random",
        summary: "rand 0.9: `.gen()` becomes `.random()` (CLOUD-1580)",
        // `gen` is a keyword in 2024, so a source still calling it parses only
        // under 2021: the edition is the recipe's, not the crate's.
        edition: Edition::E2021,
        skip: &[],
        apply: rand_random,
    },
    Recipe {
        name: "fsio-reads",
        summary: "a `std::fs` read becomes `fsio::read` / `fsio::read_to_string` (CLOUD-2692)",
        edition: Edition::E2024,
        skip: &["mutation_markers.rs", "batten-fsio/src/lib.rs"],
        apply: fsio_reads,
    },
    Recipe {
        name: "stream-capture",
        summary: "`.output()` and `.wait_with_output()` go through `stream`'s pump (#1276)",
        edition: Edition::E2024,
        skip: &["mutation_markers.rs", "batten-stream/src/lib.rs"],
        apply: stream_capture,
    },
    Recipe {
        name: "stream-keep-set",
        summary: "a `.streamed_output()` whose chain set a stream keeps it: `streamed_output_keeping` (#1276)",
        edition: Edition::E2024,
        skip: &["mutation_markers.rs", "batten-stream/src/lib.rs"],
        apply: stream_keep_set,
    },
];

/// The recipe named `name`.
#[must_use]
pub fn named(name: &str) -> Option<&'static Recipe> {
    RECIPES.iter().find(|recipe| recipe.name == name)
}

fn rand_random(source: &str, _base: &str) -> Result<String, CouldNotLook> {
    codemod::rename_method_calls(source, Edition::E2021, "gen", "random")
}

fn fsio_reads(source: &str, base: &str) -> Result<String, CouldNotLook> {
    let edition = Edition::E2024;
    let text = codemod::redirect_calls(
        source,
        edition,
        &["fs::read_to_string", "std::fs::read_to_string"],
        &format!("{base}::fsio::read_to_string"),
    )?;
    codemod::redirect_calls(
        &text,
        edition,
        &["fs::read", "std::fs::read"],
        &format!("{base}::fsio::read"),
    )
}

/// Its one blind spot, as run on this tree: a call inside a macro's arguments
/// is not renamed (one, `cli.rs`). The compiler names it.
fn stream_capture(source: &str, base: &str) -> Result<String, CouldNotLook> {
    let edition = Edition::E2024;
    let step = |text: &str, from: &str, to: &str, trait_name: &str| {
        let renamed = codemod::rename_method_calls(text, edition, from, to)?;
        if renamed == text {
            return Ok(renamed);
        }
        codemod::import_for_calls(
            &renamed,
            edition,
            &format!("use {base}::stream::{trait_name} as _;"),
            to,
        )
    };
    let once = step(source, "output", "streamed_output", "Streamed")?;
    step(&once, "wait_with_output", "streamed_wait", "StreamedChild")
}

/// `output` defaulted only the streams a chain had NOT set; the first recipe's
/// `streamed_output` defaulted all three, which overwrote a stdin read from a
/// file and a stdout handed to a hung-up reader. Each chain that set a stream
/// names it in a `Keep`, so exactly `output`'s behaviour is restored.
fn stream_keep_set(source: &str, base: &str) -> Result<String, CouldNotLook> {
    let rewrite = |chain: &[String]| {
        let set = |stream: &str| chain.iter().any(|called| called == stream);
        let (stdin, stdout, stderr) = (set("stdin"), set("stdout"), set("stderr"));
        (stdin || stdout || stderr).then(|| {
            format!(
                "streamed_output_keeping({base}::stream::Keep {{ stdin: {stdin}, stdout: {stdout}, stderr: {stderr} }})"
            )
        })
    };
    codemod::rewrite_calls_by_chain(source, Edition::E2024, "streamed_output", &rewrite)
}
