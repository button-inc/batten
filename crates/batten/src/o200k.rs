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
//! tiktoken-rs. The pre-tokenizer is a DFA `build.rs` serializes, read in
//! place: no process compiles a regex either.

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
    // `is_empty` rather than `low < high`: the same test, and the comparison's
    // `<=` mutant spins forever on a piece no token is — a hang, not a count.
    while !(low..high).is_empty() {
        // `midpoint` rather than `low + (high - low) / 2`: the same value, and
        // the spelled-out form's `% 2` mutant is a correct linear search — a
        // survivor no count could tell apart, only a clock.
        let middle = low.midpoint(high);
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
    if piece.len() < 2 {
        return 1;
    }
    // A SHORTCUT, NOT A RULE: over the whole table, every entry that is one
    // pre-tokenizer piece merges back to itself (checked exhaustively when this
    // was split from the length test), so the merge below would answer 1 here
    // too. Kept for its cost — the common piece is one token — and as its own
    // test because, joined to the length test, its `&&` mutant could only
    // survive.
    if rank(piece).is_some() {
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
    // Every part is a candidate: the closing sentinel's rank is `u32::MAX` and
    // never rewritten (a merge rewrites only `i - 1` and `i`, both before it), so
    // the filter already excludes it and a `take` stopping short of it was a
    // second statement of the same bound.
    while let Some((i, _)) = parts
        .iter()
        .enumerate()
        .filter(|(_, (_, rank))| *rank != u32::MAX)
        .min_by_key(|(i, (_, rank))| (*rank, *i))
    {
        if i > 0 {
            parts[i - 1].1 = pair(&parts, i - 1);
        }
        parts[i].1 = pair(&parts, i);
        parts.remove(i + 1);
    }
    parts.len() - 1
}

static DFA_BYTES: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/o200k_dfa.bin"));

/// The pre-tokenizer: `build.rs`'s serialized sparse DFA, read in place.
fn dfa() -> Option<&'static regex_automata::dfa::sparse::DFA<&'static [u8]>> {
    static DFA: OnceLock<Option<regex_automata::dfa::sparse::DFA<&'static [u8]>>> = OnceLock::new();
    DFA.get_or_init(|| {
        regex_automata::dfa::sparse::DFA::from_bytes(DFA_BYTES)
            .ok()
            .map(|(dfa, _)| dfa)
    })
    .as_ref()
}

/// The pre-tokenizer's pieces of `text`, in order.
///
/// Anchored forward searches from the end of the last piece. o200k's pattern
/// ends `\s+(?!\S)|\s+`; the DFA has `\s+` alone, so a whitespace run with no
/// newline, two or more characters long and followed by a non-space, gives up
/// its last character to the next piece — exactly what the lookahead does.
//MUTANT-SUITE crates/batten/src/o200k.rs
//MUTANT lookahead-untrimmed|s@^                .is_some_and(\x7cnext\x7c !next.is_whitespace())$@                .is_some_and(\x7c_\x7c false)@|counts_match_tiktoken
fn pieces<'a>(
    dfa: &'a regex_automata::dfa::sparse::DFA<&'static [u8]>,
    text: &'a str,
) -> impl Iterator<Item = &'a str> {
    use regex_automata::dfa::Automaton as _;
    let mut at = 0;
    std::iter::from_fn(move || {
        let remaining = text.get(at..).filter(|remaining| !remaining.is_empty())?;
        let input = regex_automata::Input::new(text)
            .range(at..)
            .anchored(regex_automata::Anchored::Yes);
        // EVERY POSITION MATCHES: each alternative of o200k's pattern consumes
        // a character, and a probe over control, format, combining, private-use
        // and separator characters found none the DFA fails at (measured on
        // #1132). The skip-one-character fallback this replaces was therefore
        // unreachable, and cargo-mutants' mutants of it could only survive. A
        // DFA that cannot search at all ends the pieces with the rest whole.
        let found = match dfa.try_search_fwd(&input) {
            // `!=` rather than `>`: an anchored forward match never ends
            // before `at`, so the two agree, and `>`'s `>=` mutant would be
            // equivalent — a survivor no case could kill.
            Ok(Some(found)) if found.offset() != at => found,
            _ => {
                at = text.len();
                return Some(remaining);
            }
        };
        let mut end = found.offset();
        let piece = text.get(at..end).unwrap_or_default();
        let rest = text.get(end..).unwrap_or_default();
        if piece.chars().all(char::is_whitespace)
            && !piece.contains(['\r', '\n'])
            && piece.chars().nth(1).is_some()
            && rest
                .chars()
                .next()
                .is_some_and(|next| !next.is_whitespace())
        {
            end -= piece.chars().last().map_or(0, char::len_utf8);
        }
        let out = text.get(at..end).unwrap_or_default();
        at = end;
        Some(out)
    })
}

/// How many `o200k_base` tokens `text` is.
///
/// A DFA that cannot load (it is a build-time constant, so this does not
/// happen) counts bytes: an over-count, so a bound errs toward a pointer.
#[must_use]
pub fn tokens(text: &str) -> u64 {
    let Some(dfa) = dfa() else {
        return text.len() as u64;
    };
    pieces(dfa, text)
        .map(|piece| piece_tokens(piece.as_bytes()) as u64)
        .sum()
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    /// A rank is the token's own id, read from the rank column at the found
    /// entry, and a byte string that is no token has none.
    ///
    /// Fails by: any operator of the rank column's index replaced — every one
    /// reads a neighbouring word, a different token's rank or an offset.
    #[test]
    fn a_rank_is_tiktokens_own_token_id() {
        // Each id as `tiktoken_rs::o200k_base().encode_ordinary` gives it, one
        // token per piece.
        for (piece, id) in [("hello", 24912), (" world", 2375), ("!", 0), (" the", 290)] {
            assert_eq!(super::rank(piece.as_bytes()), Some(id), "{piece:?}");
        }
        assert_eq!(super::rank(b"no such token, surely, at all"), None);
    }

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
