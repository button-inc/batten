//! Count distinct gates per context window, and what follows each refusal
//! (CLOUD-2141).
//!
//! # A report, never a gate
//!
//! Nothing in `verify` or the hk gate calls this, for `refusal-render-bench`'s
//! reason: it answers a question about a MEASUREMENT, the number a per-gate doc
//! budget is divided by. It exits 0 having measured and 1 when a transcript or
//! the config cannot be read, and never 2 — it decides nothing.
//!
//! # No tokenizer
//!
//! The shipped binary must not link one (workspace `Cargo.toml`, CLOUD-1284 arm
//! 4), and the census reads the transcript's own estimate, so this does not
//! either. Exact-tokenizer calibration is CLOUD-2143's, over the doc corpus.
//!
//! # Pointer-only
//!
//! Counts and percentages, never a byte of any transcript (rule 4): the text
//! dies inside `transcript::parse` before this file sees a record.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use batten::hook::RecordShape;
use batten::hookcost::{Follow, Window, windows};
use batten::transcript::parse;

fn main() -> anyhow::Result<()> {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    anyhow::ensure!(
        !paths.is_empty(),
        "usage: window-census <transcript.jsonl>..."
    );
    // THE COMMITTED AUTHORITY, for `refusal-render-bench`'s reason: a route a
    // refusal is followed by is one this repository actually declares.
    let config = batten::config::load(Path::new("batten.toml"))?;
    let registry = batten::policy::registry_for(&config.verdicts)?;
    let routes: BTreeMap<String, Vec<String>> = registry
        .iter()
        .map(|entry| {
            let targets = batten::verdict::command_routes(&registry, &entry.id)
                .into_iter()
                .map(str::to_owned)
                .collect();
            (entry.id.clone(), targets)
        })
        .collect();
    let mut segments: Vec<Window> = Vec::new();
    for path in &paths {
        let body = std::fs::read_to_string(path)?;
        let stream = parse(&body, path, RecordShape::Jsonl)?;
        segments.extend(windows(&stream, &routes).segments);
    }
    #[expect(
        clippy::print_stdout,
        reason = "an example target is a binary boundary; the report is its only output"
    )]
    {
        print!("{}", report(paths.len(), &segments));
    }
    Ok(())
}

/// The whole report, as Markdown rows.
fn report(transcripts: usize, segments: &[Window]) -> String {
    let mut distinct: Vec<usize> = segments.iter().map(|window| window.distinct).collect();
    distinct.sort_unstable();
    let n = distinct.len();
    let total = |pick: fn(&Window) -> usize| segments.iter().map(pick).sum::<usize>();
    let refusals = total(|window| window.refusals);
    let mut out = format!(
        "| transcripts | windows |\n| --: | --: |\n| {transcripts} | {n} |\n\n\
         | distinct gates per window | value |\n| -- | --: |\n\
         | mean | {:.1} |\n| p95 | {} |\n| max | {} |\n\n",
        mean(total(|window| window.distinct), n),
        percentile(&distinct, 95),
        distinct.last().copied().unwrap_or_default(),
    );
    // Writing into a `String` cannot fail, so the `fmt::Result`s are dropped.
    let _ = write!(
        out,
        "| tokens per window (bytes/4) | mean |\n| -- | --: |\n\
         | full arms | {:.0} |\n| pointer arms | {:.0} |\n| unlabelled | {:.0} |\n\n",
        mean(total(|window| window.full_tokens), n),
        mean(total(|window| window.pointer_tokens), n),
        mean(total(|window| window.unlabelled_tokens), n),
    );
    let _ = write!(
        out,
        "| refusals | count | share |\n| -- | --: | --: |\n| all | {refusals} | 100% |\n\
         | unlabelled | {} | {:.0}% |\n",
        total(|window| window.unlabelled_refusals),
        share(total(|window| window.unlabelled_refusals), refusals),
    );
    for (slot, bucket) in Follow::ALL.iter().enumerate() {
        let count: usize = segments
            .iter()
            .map(|window| window.buckets.get(slot).copied().unwrap_or_default())
            .sum();
        let _ = writeln!(
            out,
            "| next call: {bucket:?} | {count} | {:.0}% |",
            share(count, refusals)
        );
    }
    out
}

#[expect(
    clippy::cast_precision_loss,
    reason = "a report average over counts far below 2^52"
)]
fn mean(sum: usize, n: usize) -> f64 {
    if n == 0 { 0.0 } else { sum as f64 / n as f64 }
}

#[expect(
    clippy::cast_precision_loss,
    reason = "a report percentage over counts far below 2^52"
)]
fn share(part: usize, whole: usize) -> f64 {
    if whole == 0 {
        0.0
    } else {
        part as f64 * 100.0 / whole as f64
    }
}

/// The nearest-rank percentile of an ascending list.
fn percentile(sorted: &[usize], pct: usize) -> usize {
    if sorted.is_empty() {
        return 0;
    }
    let rank = (pct * sorted.len()).div_ceil(100).max(1);
    sorted.get(rank - 1).copied().unwrap_or_default()
}
