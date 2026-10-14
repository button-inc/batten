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
//MUTANT-SUITE crates/batten/src/o200k.rs

use std::io::Write as _;

/// The two special tokens: never produced by ordinary encoding, so never in
/// the merge table.
const SPECIAL_RANKS: [u32; 2] = [199_999, 200_018];

type Built = Result<(), Box<dyn std::error::Error>>;

fn main() -> Built {
    println!("cargo:rerun-if-changed=build.rs");
    let out = std::path::PathBuf::from(std::env::var_os("OUT_DIR").ok_or("cargo sets OUT_DIR")?);
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
