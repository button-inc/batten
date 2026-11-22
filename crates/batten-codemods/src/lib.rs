//! Named codemods: each migration this repository ran, kept as a recipe (#1276).
//!
//! A recipe is a migration already proven on this tree, written only in
//! `batten`'s codemod primitives ([`codemod::rename_method_calls`],
//! [`codemod::redirect_calls`], [`codemod::import_for_calls`],
//! [`codemod::rewrite_calls_by_chain`], [`codemod::rewrite_paths`]). This crate is never
//! released: a recipe reaches the shipped binary only when a preset vendors it. It is kept rather than thrown away with its driver for
//! two reasons. A consumer making the same move runs it as one call, which is
//! what vendoring one into a preset will mean. And the tree it already migrated
//! is its regression test: run again, it rewrites nothing.
//!
//! `cargo run -p batten-codemods --example codemod -- <recipe>` runs one by name.

pub mod cut;
pub mod fix;

use std::collections::BTreeMap;

use batten::codemod::{self, CouldNotLook, Edition};
use batten::item_index;

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
    Recipe {
        name: "stream-adapter-exec",
        summary: "`Streamed`, `StreamedChild` and `Keep` move from `stream` to `capture`, beside the placed spawn in `exec` (#1276; CLOUD-2793 retired the `exec` re-export)",
        edition: Edition::E2024,
        skip: &["mutation_markers.rs"],
        apply: stream_adapter_exec,
    },
    Recipe {
        name: "one-rust-parse",
        summary: "every `ra_ap_syntax` parse goes through `batten_facts::source::rust_parse`, the one lossless parse (CLOUD-1008)",
        edition: Edition::E2024,
        skip: &["mutation_markers.rs", "batten-facts/src/source.rs"],
        apply: one_rust_parse,
    },
];

/// The recipe named `name`.
#[must_use]
pub fn named(name: &str) -> Option<&'static Recipe> {
    RECIPES.iter().find(|recipe| recipe.name == name)
}

/// One named migration whose rewrite of a file depends on the other files:
/// moving a path to an item's home needs every crate's modules resolved.
#[derive(Debug, Clone, Copy)]
pub struct TreeRecipe {
    /// What the driver is asked for.
    pub name: &'static str,
    /// The move, in one line.
    pub summary: &'static str,
    /// Path suffixes it never rewrites, as [`Recipe::skip`].
    pub skip: &'static [&'static str],
    /// The rewrite of a tree: every `.rs` file (path to text) and every
    /// `Cargo.toml` (path to text), both relative to the tree's root, in;
    /// each file whose text changes, out.
    pub apply: fn(
        files: &BTreeMap<String, String>,
        manifests: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String>,
}

/// Every tree recipe, in the order they were first run.
pub const TREE_RECIPES: &[TreeRecipe] = &[
    TreeRecipe {
        name: "respell-through-shims",
        summary: "a path through a `pub use crate::…` below a crate root names the item's home, and the shim goes private (CLOUD-2793)",
        skip: &["mutation_markers.rs"],
        apply: item_index::respell_through_shims,
    },
    TreeRecipe {
        name: "split-inline-modules",
        summary: "a module file that is nothing but inline modules becomes one file per module, paths unchanged (CLOUD-2793)",
        skip: &["mutation_markers.rs"],
        apply: split_inline_modules,
    },
    TreeRecipe {
        name: "impl-to-extension-trait",
        summary: "an inherent impl in a higher layer than its type becomes that layer's extension trait, so behaviour stays above the vocabulary (CLOUD-2793)",
        skip: &["mutation_markers.rs"],
        apply: impl_to_extension_trait,
    },
];

/// `split-inline-modules` over the whole tree: the predicate is a file's
/// shape, not its package, so manifests are not needed.
fn split_inline_modules(
    files: &BTreeMap<String, String>,
    _manifests: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    batten::module_graph::split_inline_modules(files)
}

/// `impl-to-extension-trait` over every package `manifests` declares: each
/// package's `src/` is one run, importing the trait from outside `src/` by
/// the package's crate name.
fn impl_to_extension_trait(
    files: &BTreeMap<String, String>,
    manifests: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut changed: BTreeMap<String, String> = BTreeMap::new();
    for (path, text) in manifests {
        let (Some(dir), Some(name)) = (path.strip_suffix("Cargo.toml"), package_name(text)) else {
            continue;
        };
        // Each run reads the tree as the runs before it left it.
        let current: BTreeMap<String, String> = files
            .iter()
            .map(|(key, text)| {
                let now = changed.get(key).unwrap_or(text);
                (key.clone(), now.clone())
            })
            .collect();
        changed.extend(batten::module_graph::impls_to_extension_traits(
            &format!("{dir}src"),
            &name.replace('-', "_"),
            &current,
        ));
    }
    changed
}

/// The `name` of a manifest's `[package]` table, read from its lines: the
/// one fact this needs does not warrant a TOML dependency.
fn package_name(manifest: &str) -> Option<String> {
    let mut in_package = false;
    for line in manifest.lines().map(str::trim) {
        if line.starts_with('[') {
            in_package = line == "[package]";
        } else if in_package && let Some(value) = line.strip_prefix("name") {
            let value = value.trim_start().strip_prefix('=')?.trim();
            return Some(value.trim_matches('"').to_owned());
        }
    }
    None
}

/// The tree recipe named `name`.
#[must_use]
pub fn named_tree(name: &str) -> Option<&'static TreeRecipe> {
    TREE_RECIPES.iter().find(|recipe| recipe.name == name)
}

/// The parse moves to its one home, arguments untouched: the edition each site
/// passed is the edition it keeps.
fn one_rust_parse(source: &str, _base: &str) -> Result<String, CouldNotLook> {
    codemod::redirect_calls(
        source,
        Edition::E2024,
        &["SourceFile::parse", "ra_ap_syntax::SourceFile::parse"],
        "batten_facts::source::rust_parse",
    )
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
            &format!("use {base}::capture::{trait_name} as _;"),
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
                "streamed_output_keeping({base}::capture::Keep {{ stdin: {stdin}, stdout: {stdout}, stderr: {stderr} }})"
            )
        })
    };
    codemod::rewrite_calls_by_chain(source, Edition::E2024, "streamed_output", &rewrite)
}

/// `batten-stream` carried the process adapter, a spawn in a module the
/// spawn-placement table does not place. It moved beside `exec`, the placed
/// child-process boundary, into `capture`, and every path to it moves with it
/// (it named `exec` until CLOUD-2793 retired that re-export). Its blind spot:
/// a path inside a macro's arguments, which the compiler names.
fn stream_adapter_exec(source: &str, base: &str) -> Result<String, CouldNotLook> {
    let mut text = source.to_owned();
    for item in ["Streamed", "StreamedChild", "Keep"] {
        text = codemod::rewrite_paths(
            &text,
            Edition::E2024,
            &format!("{base}::stream::{item}"),
            &format!("{base}::capture::{item}"),
        )?;
    }
    Ok(text)
}
