//! `o200k_base` token counting over a static table (CLOUD-2224).
//!
//! **Nothing is built at runtime.** The vocabulary is `build.rs`'s `o200k.bin`
//! in read-only data: a rank is a binary search over it, and the OS pages in
//! only what a count touches. Building the vocabulary per process cost
//! 120-165 ms (tiktoken-rs) or 56-65 ms (bpe-openai) against a whole hook call
//! at p50 21-31 ms; every hook call is a fresh process, so that cost would be
//! paid on almost every result.
//!
//! The merge is tiktoken's own byte-pair merge over the same pre-tokenizer
//! pieces, and `tests::counts_match_tiktoken` holds the counts identical to
//! tiktoken-rs. The pre-tokenizer regex still compiles once per process
//! (measured 4.7-6.7 ms), and only when a count is asked for.

use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/o200k_pattern.rs"));

static TABLE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/o200k.bin"));

/// The `index`th little-endian `u32` of the table.
fn word(index: usize) -> u32 {
    let at = index * 4;
    TABLE
        .get(at..at + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map_or(u32::MAX, u32::from_le_bytes)
}

fn count() -> usize {
    word(0) as usize
}

/// The bytes of the `entry`th token in sorted order.
fn entry(entry: usize) -> &'static [u8] {
    let entries = count();
    let blob = 4 * (1 + (entries + 1) + entries);
    let from = word(1 + entry) as usize;
    let to = word(2 + entry) as usize;
    TABLE.get(blob + from..blob + to).unwrap_or_default()
}

/// The rank of `piece`, or `None` where it is not one token.
fn rank(piece: &[u8]) -> Option<u32> {
    let entries = count();
    let (mut low, mut high) = (0, entries);
    while low < high {
        let middle = low + (high - low) / 2;
        match entry(middle).cmp(piece) {
            std::cmp::Ordering::Less => low = middle + 1,
            std::cmp::Ordering::Greater => high = middle,
            std::cmp::Ordering::Equal => return Some(word(1 + (entries + 1) + middle)),
        }
    }
    None
}

/// How many tokens `piece` is: tiktoken's byte-pair merge, counted.
fn piece_tokens(piece: &[u8]) -> usize {
    if piece.len() < 2 || rank(piece).is_some() {
        return 1;
    }
    let pair = |parts: &[(usize, u32)], i: usize| -> u32 {
        if i + 3 < parts.len() {
            rank(piece.get(parts[i].0..parts[i + 3].0).unwrap_or_default()).unwrap_or(u32::MAX)
        } else {
            u32::MAX
        }
    };
    let mut parts: Vec<(usize, u32)> = (0..piece.len() - 1)
        .map(|i| {
            (
                i,
                rank(piece.get(i..i + 2).unwrap_or_default()).unwrap_or(u32::MAX),
            )
        })
        .collect();
    parts.push((piece.len() - 1, u32::MAX));
    parts.push((piece.len(), u32::MAX));
    loop {
        let Some((i, _)) = parts
            .iter()
            .take(parts.len() - 1)
            .enumerate()
            .filter(|(_, (_, rank))| *rank != u32::MAX)
            .min_by_key(|(i, (_, rank))| (*rank, *i))
        else {
            break;
        };
        if i > 0 {
            parts[i - 1].1 = pair(&parts, i - 1);
        }
        parts[i].1 = pair(&parts, i);
        parts.remove(i + 1);
    }
    parts.len() - 1
}

fn splitter() -> Option<&'static fancy_regex::Regex> {
    static REGEX: OnceLock<Option<fancy_regex::Regex>> = OnceLock::new();
    REGEX
        .get_or_init(|| fancy_regex::Regex::new(PATTERN).ok())
        .as_ref()
}

/// How many `o200k_base` tokens `text` is.
///
/// A pattern that cannot compile (it is a build-time constant, so this does
/// not happen) counts bytes: an over-count, so a bound errs toward a pointer.
#[must_use]
pub fn tokens(text: &str) -> u64 {
    let Some(regex) = splitter() else {
        return text.len() as u64;
    };
    regex
        .find_iter(text)
        .filter_map(Result::ok)
        .map(|piece| piece_tokens(piece.as_str().as_bytes()) as u64)
        .sum()
}

#[cfg(test)]
mod tests {
    #[test]
    fn counts_match_tiktoken() {
        // The anti-drift case: the static table and the merge loop give exactly
        // tiktoken-rs's count, over prose, code, unicode and whitespace runs.
        let bpe = tiktoken_rs::o200k_base().expect("reference");
        for text in [
            "",
            "hello world",
            "payload line of a large log, with some \"quoted\" text and a tab\there\n",
            "fn main() {\n    println!(\"{}\", 1 + 2);\n}\n\n\n   trailing   ",
            "Ünïcödé — émoji 🎉🎉 and 中文字符 and Ελληνικά, 12345678 numbers",
            "I'll they're we've  \r\n\r\n tabs\t\t\tand    spaces",
            include_str!("o200k.rs"),
        ] {
            assert_eq!(
                super::tokens(text),
                bpe.encode_ordinary(text).len() as u64,
                "counts diverge on {text:?}"
            );
        }
    }
}
