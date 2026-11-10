//! Build-time tables (CLOUD-2224).
//!
//! The `o200k_base` vocabulary as a static table in the binary's read-only
//! data, so counting tokens in a hook process never BUILDS the vocabulary:
//! measured, building it at runtime cost 120-165 ms and ~53 MiB per process
//! (tiktoken-rs) or 56-65 ms and ~70 MiB (bpe-openai), against a whole hook call
//! at p50 21-31 ms. Here it is built once, at compile time, from tiktoken-rs,
//! the one source of both the vocabulary and the pre-tokenizer pattern.
//!
//! `o200k.bin`, little-endian `u32`s then bytes:
//! `count`, `offsets[count + 1]` into the blob, `ranks[count]`, the blob — the
//! entries sorted by their bytes, so a rank is a binary search over the blob.
//!
//! No test target compiles this file; what it writes is judged where it is
//! read, by `o200k`'s parity case against tiktoken itself.
//!
//! It also REFUSES TO BUILD a crate carrying a hand-written Rust mutation
//! marker or a second cargo-mutants argv ([`mutation_markers`], CLOUD-2253):
//! the Rust tier is cargo-mutants' alone, and a build is the one step nothing
//! skips.

use std::io::Write as _;
use std::path::{Path, PathBuf};

#[path = "src/mutation_markers.rs"]
mod mutation_markers;

/// The two special tokens: never produced by ordinary encoding, so never in
/// the merge table.
const SPECIAL_RANKS: [u32; 2] = [199_999, 200_018];

type Built = Result<(), Box<dyn std::error::Error>>;

fn main() -> Built {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").ok_or("cargo sets CARGO_MANIFEST_DIR")?,
    );
    refuse_hand_rolled_mutation(&manifest)?;
    let out = PathBuf::from(std::env::var_os("OUT_DIR").ok_or("cargo sets OUT_DIR")?);
    // THE TABLES ARE BUILT ONCE PER `OUT_DIR`, which cargo keys on this package
    // and its dependencies: the scan above reruns this script on every source
    // edit, and rebuilding a 200k-entry table each time would put seconds on
    // every build for bytes that cannot have changed.
    if ["o200k.bin", "o200k_dfa.bin", "o200k_pattern.rs"]
        .iter()
        .all(|file| out.join(file).is_file())
    {
        return Ok(());
    }
    let bpe = tiktoken_rs::o200k_base()?;
    let mut entries: Vec<(Vec<u8>, u32)> = (0..=200_018_u32)
        .filter(|rank| !SPECIAL_RANKS.contains(rank))
        .filter_map(|rank| bpe.decode_bytes(&[rank]).ok().map(|bytes| (bytes, rank)))
        .collect();
    entries.sort_unstable();
    let count = u32::try_from(entries.len())?;
    let mut offsets = Vec::with_capacity(entries.len() + 1);
    let mut blob = Vec::new();
    for (bytes, _) in &entries {
        offsets.push(u32::try_from(blob.len())?);
        blob.extend_from_slice(bytes);
    }
    offsets.push(u32::try_from(blob.len())?);
    let mut table = Vec::with_capacity(4 + offsets.len() * 4 + entries.len() * 4 + blob.len());
    table.extend_from_slice(&count.to_le_bytes());
    for offset in &offsets {
        table.extend_from_slice(&offset.to_le_bytes());
    }
    for (_, rank) in &entries {
        table.extend_from_slice(&rank.to_le_bytes());
    }
    table.extend_from_slice(&blob);
    std::fs::write(out.join("o200k.bin"), &table)?;
    // THE PRE-TOKENIZER AS A DFA, built here so no process compiles a regex
    // (measured at 4.7-6.7 ms per process with fancy-regex, against a 10 ms hook
    // target). o200k's one lookahead alternative, `\s+(?!\S)`, is not
    // DFA-expressible: it becomes `\s+`, and `o200k::pieces` trims a run that
    // the lookahead would have left one character short.
    let lookahead = r"|\s+(?!\S)|\s+";
    let source = tiktoken_rs::O200K_BASE_PAT_STR;
    if !source.ends_with(lookahead) {
        return Err(format!("o200k's pattern changed shape: {source}").into());
    }
    let plain = format!("{}|\\s+", source.trim_end_matches(lookahead));
    let dfa = regex_automata::dfa::dense::Builder::new()
        .configure(
            regex_automata::dfa::dense::Config::new()
                .start_kind(regex_automata::dfa::StartKind::Anchored),
        )
        .build(&plain)?
        .to_sparse()?;
    std::fs::write(out.join("o200k_dfa.bin"), dfa.to_bytes_little_endian())?;
    let mut pattern = std::fs::File::create(out.join("o200k_pattern.rs"))?;
    writeln!(
        pattern,
        "/// `o200k_base`'s pre-tokenizer, copied from tiktoken-rs at build time.\npub const PATTERN: &str = {:?};",
        tiktoken_rs::O200K_BASE_PAT_STR
    )?;
    Ok(())
}

/// Refuse the build where the crate's Rust carries a mutation marker anywhere, or
/// builds a cargo-mutants argv outside its one site ([`mutation_markers`]).
/// Pointers only: `path:line`, never the line (rule 4).
fn refuse_hand_rolled_mutation(manifest: &Path) -> Built {
    let mut sources = Vec::new();
    for dir in ["src", "tests", "benches", "examples"] {
        let root = manifest.join(dir);
        println!("cargo:rerun-if-changed={}", root.display());
        rust_files(&root, &mut sources);
    }
    sources.push(manifest.join("build.rs"));
    let mut markers = Vec::new();
    let mut argv_sites = Vec::new();
    for path in &sources {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let relative = path
            .strip_prefix(manifest)
            .unwrap_or(path)
            .display()
            .to_string();
        markers.extend(
            mutation_markers::marker_lines(&text)
                .into_iter()
                .map(|line| format!("{relative}:{line}")),
        );
        let argv = text.matches(mutation_markers::CARGO_MUTANTS_ARGV).count();
        if argv > 0 {
            argv_sites.push((relative, argv));
        }
    }
    if !markers.is_empty() {
        return Err(format!(
            "hand-written Rust mutation marker(s) at {}: cargo-mutants owns every Rust source and \
             reads none of them (CLOUD-2253); delete them",
            markers.join(", ")
        )
        .into());
    }
    let one_site = argv_sites.len() == 1
        && argv_sites[0] == (mutation_markers::CARGO_MUTANTS_SITE.to_owned(), 1);
    if !one_site {
        let sites: Vec<String> = argv_sites
            .iter()
            .map(|(path, count)| format!("{path} ({count})"))
            .collect();
        return Err(format!(
            "a cargo-mutants argv is built at [{}], not once in {}: cargo-mutants runs as \
             itself through `mutate::cargo_mutants`, never a second harness (CLOUD-2253)",
            sites.join(", "),
            mutation_markers::CARGO_MUTANTS_SITE
        )
        .into());
    }
    Ok(())
}

/// Every `.rs` file under `dir`, recursively; a missing directory is none.
fn rust_files(dir: &Path, into: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_files(&path, into);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            into.push(path);
        }
    }
}
