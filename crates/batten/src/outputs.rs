//! Output predicates over a wrapped command's captured streams (CLOUD-117).
//!
//! A command can lie about completion: it exits `0` while its own output carries
//! a line meaning "done isn't really done" — a `warning[duplicate]` from a tool
//! configured to warn, a deprecation notice, a "skipped N files" summary. That is
//! the *wrong completion signal* half of Batten's threat model, and for a tool
//! with no severity knob of its own the only evidence is a string in a stream
//! paired with an exit code that says success.
//!
//! ## A match always fails, and that is the design rather than a shortcut
//!
//! There is deliberately **no severity field and no exec-local promotion knob.**
//! The only surface an agent acts on is the exit code, so a finding that exits `0`
//! is operationally invisible to it — a "warn-but-pass" output match would
//! reproduce the exact false green this predicate exists to kill. You declare a
//! pattern here *because* the string means not-actually-done; that is a hard fail
//! by construction.
//!
//! It is therefore **not** a `fail_on_warning` consumer, and `severity.rs` says so
//! in its own module docs. A promotion knob would be a weakening surface whose
//! "warn" setting an agent could not perceive.
//!
//! ## Literal, not regex
//!
//! The match is a case-sensitive literal substring. The issue's own guidance
//! asks for "a fixed, reviewable literal" — a pattern a reviewer can read
//! without evaluating it.
//!
//! This module once justified that by "the crate carries no regex dependency",
//! and added that adding one "is a decision about the whole rule vocabulary, not
//! a detail of this predicate". That decision has since been taken, narrowly:
//! CLOUD-283 gave `RuleKind::Forbid` a `regex` alternative and an `exclude`
//! column, because a flag cluster judged by its letters is genuinely a shape and
//! no enumeration of spellings survives contact with one.
//!
//! **It was taken for `forbid` and nowhere else, and this predicate is one of
//! the places it was deliberately not taken.** The dependency now exists, so the
//! reason has to stand on its own: an `exec_pattern` decides whether a wrapped
//! command's *output* betrays a failure it did not report, and a reviewer
//! reading the config should be able to see what would trip it without
//! evaluating an expression in their head. `markers.rs` states the sibling case
//! in its own words — a count must not become a function of an expression.
//!
//! ## Pointer-only is decided elsewhere, and that is the point
//!
//! [`Hit::line_text`] renders `stream:line <id>` and never the matched bytes, and
//! this module's own tests say so. That was the whole of the guarantee for a
//! while, and it was the wrong shape for it: a per-module assertion answers "does
//! *this* emitter leak", when the law (non-negotiable rule 4, house-style §6) is
//! a claim about **every** check. An emitter that leaked would have been caught
//! here only if somebody thought to write the case here.
//!
//! `crates/batten/tests/it/pointer_only.rs` decides it instead, at the process
//! boundary every emitter converges on: a corpus in which every byte a check can
//! read is a canary, crossed with a census over the whole verb surface. A wrapped
//! command's output is the likeliest place in this engine for a secret to appear,
//! which is why this module is one of the canary's seeded sources rather than the
//! judge of whether it obeys the law.
//!
//! ## Batten only ever ADDS failure
//!
//! A child that already exited non-zero passes its code through untouched: there
//! is nothing to promote, and re-deciding a failure Batten did not diagnose would
//! make the wrapper's verdict unreadable. Only `0` is promotable.

use serde::{Deserialize, Serialize};

use crate::capture::Stream;
use crate::error::UsageError;

/// Which captured stream a pattern is matched against.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Watched {
    /// The child's standard output only.
    Stdout,
    /// The child's standard error only.
    Stderr,
    /// Both streams.
    ///
    /// The default, and deliberately the *widest* reading: a tool that moves a
    /// warning from one stream to the other between releases would otherwise
    /// silently stop being gated, and a pattern that quietly matches nothing is
    /// the failure this whole feature exists to prevent.
    #[default]
    Both,
}

impl Watched {
    /// Every value, so anything ranging over the vocabulary is derived.
    pub const ALL: &'static [Watched] = &[Watched::Stdout, Watched::Stderr, Watched::Both];

    /// The stable token this value is written as.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Watched::Stdout => "stdout",
            Watched::Stderr => "stderr",
            Watched::Both => "both",
        }
    }

    /// Whether this selection covers `stream`.
    #[must_use]
    pub const fn covers(self, stream: Stream) -> bool {
        match self {
            Watched::Both => true,
            Watched::Stdout => matches!(stream, Stream::Stdout),
            Watched::Stderr => matches!(stream, Stream::Stderr),
        }
    }
}

/// One declared output predicate: a literal that must not appear.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OutputPattern {
    /// The stable identifier a match is reported under.
    ///
    /// Required, and it is what keeps the report pointer-only: a finding names
    /// `stream:line` plus this id, never the line that matched. Without an id the
    /// only way to say *which* pattern fired would be to echo the bytes.
    pub id: String,
    /// The case-sensitive literal that must not appear in the watched stream.
    pub pattern: String,
    /// Which stream to watch. Defaults to both.
    #[serde(default)]
    pub stream: Watched,
    /// What the caller should do about it.
    ///
    /// Required, unlike on a file rule. A file finding is a `path:line` a reader
    /// can open; a promoted exit code is all a caller gets back, so a refusal
    /// naming only its id would be un-actionable (CLOUD-122).
    pub reason: String,
}

/// Where a pattern matched: the stream and the 1-based line within it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Hit {
    /// The stream the match was found in.
    pub stream: &'static str,
    /// The 1-based line number within that stream.
    pub line: usize,
    /// The id of the pattern that matched.
    pub id: String,
}

impl Hit {
    /// The pointer line this hit renders as: `<stream>:<line> <id>`.
    ///
    /// Exactly a finding's `path:line rule-id` shape, so a caller that already
    /// parses `check` output needs no second parser — and never the matched bytes
    /// (non-negotiable rule 4). A wrapped command's output is the most likely
    /// place for a secret to appear in this whole engine, which is what makes
    /// pointer-only load-bearing here rather than stylistic.
    #[must_use]
    pub fn line_text(&self) -> String {
        format!("{}:{} {}", self.stream, self.line, self.id)
    }
}

/// Refuse a malformed `[[exec_pattern]]` table at load, so a typo cannot sit inert.
///
/// # Errors
///
/// As [`validate_named`].
pub fn validate(patterns: &[OutputPattern]) -> anyhow::Result<()> {
    validate_named(patterns, "exec_pattern")
}

/// Refuse a malformed `[[verify_environment_pattern]]` table at load.
///
/// # A SECOND ENTRY POINT OVER ONE IMPLEMENTATION, and both reasons are real
///
/// The checks are identical — same type, same four ways to be malformed — so the
/// body is [`validate_named`] and this adds none of its own. What it adds is a
/// NAME, twice over.
///
/// It names the table in the refusal. `validate` spelled `exec_pattern` into
/// every message, so the second table's malformed row would have reported a row
/// in a table the author had not touched — a pointer to the wrong file, which is
/// worse than no pointer.
///
/// And it names the table to `config.rs`'s census, which resolves each declared
/// table to its validator BY THE CALL STRING. Two tables sharing
/// `outputs::validate(` are one call site to that gate: it finds the first,
/// reads the class wrapping it, and reports the second as unwrapped. A distinct
/// entry point is what makes the census able to see both.
///
/// # Errors
///
/// As [`validate_named`].
pub fn validate_environment(patterns: &[OutputPattern]) -> anyhow::Result<()> {
    validate_named(patterns, "verify_environment_pattern")
}

/// Refuse a malformed pattern table at load, so a typo cannot sit inert.
///
/// `table` is the caller's own table name, carried into every message so a
/// refusal points at the file and row an author has to edit.
///
/// # Errors
///
/// Returns a [`UsageError`] for an empty id, pattern or reason, or a duplicate id.
pub fn validate_named(patterns: &[OutputPattern], table: &str) -> anyhow::Result<()> {
    let mut seen: Vec<&str> = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        if pattern.id.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "{table}: id must not be empty — it is what a match is reported as"
            )));
        }
        if pattern.pattern.is_empty() {
            return Err(UsageError::raise(format!(
                "{table} {}: pattern must not be empty — an empty literal matches every run",
                pattern.id
            )));
        }
        if pattern.reason.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "{table} {}: reason is required — a promoted exit code is all the caller gets back",
                pattern.id
            )));
        }
        if seen.contains(&pattern.id.as_str()) {
            return Err(UsageError::raise(format!(
                "{table} {}: declared twice",
                pattern.id
            )));
        }
        seen.push(&pattern.id);
    }
    Ok(())
}

/// Every hit of `patterns` in one captured `stream`.
///
/// Bytes that are not valid UTF-8 are scanned line-wise as lossy text rather than
/// skipped: a tool that emits one invalid byte in a progress bar must not thereby
/// become un-gateable, and the alternative — silently scanning nothing — is the
/// false green this predicate exists to prevent.
#[must_use]
pub fn hits(patterns: &[OutputPattern], stream: Stream, bytes: &[u8]) -> Vec<Hit> {
    let text = String::from_utf8_lossy(bytes);
    let mut found = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for pattern in patterns {
            if pattern.stream.covers(stream) && line.contains(&pattern.pattern) {
                found.push(Hit {
                    stream: stream.as_str(),
                    line: index + 1,
                    id: pattern.id.clone(),
                });
            }
        }
    }
    found
}

/// The reasons behind a set of hits, deduplicated, in declaration order.
///
/// One line per distinct pattern rather than per hit: a tool that emitted the same
/// warning forty times should say what to do about it once.
#[must_use]
pub fn reasons(patterns: &[OutputPattern], found: &[Hit]) -> Vec<String> {
    patterns
        .iter()
        .filter(|pattern| found.iter().any(|hit| hit.id == pattern.id))
        .map(|pattern| format!("{}: {}", pattern.id, pattern.reason))
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn pattern(id: &str, literal: &str, stream: Watched) -> OutputPattern {
        OutputPattern {
            id: id.to_owned(),
            pattern: literal.to_owned(),
            stream,
            reason: "do the thing".to_owned(),
        }
    }

    #[test]
    fn every_watched_value_round_trips_through_its_token() {
        for watched in Watched::ALL {
            assert!(!watched.as_str().is_empty());
        }
        assert_eq!(Watched::default(), Watched::Both);
    }

    #[test]
    fn both_is_the_widest_reading_and_covers_each_stream() {
        for stream in Stream::ALL {
            assert!(Watched::Both.covers(*stream));
        }
        assert!(Watched::Stdout.covers(Stream::Stdout));
        assert!(!Watched::Stdout.covers(Stream::Stderr));
        assert!(Watched::Stderr.covers(Stream::Stderr));
        assert!(!Watched::Stderr.covers(Stream::Stdout));
    }

    #[test]
    fn a_match_points_at_its_line_and_never_carries_the_bytes() {
        let patterns = [pattern("no-warn", "warning[duplicate]", Watched::Both)];
        let found = hits(
            &patterns,
            Stream::Stdout,
            b"fine\nwarning[duplicate] serde\nalso fine\n",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2);
        assert_eq!(found[0].line_text(), "stdout:2 no-warn");
        assert!(
            !found[0].line_text().contains("serde"),
            "the pointer must never carry the matched line"
        );
    }

    #[test]
    fn a_pattern_scoped_to_one_stream_ignores_the_other() {
        let patterns = [pattern("only-err", "boom", Watched::Stderr)];
        assert!(hits(&patterns, Stream::Stdout, b"boom\n").is_empty());
        assert_eq!(hits(&patterns, Stream::Stderr, b"boom\n").len(), 1);
    }

    #[test]
    fn invalid_utf8_is_scanned_lossily_rather_than_skipped() {
        // A tool that emits one bad byte in a progress bar must not become
        // un-gateable; scanning nothing would be the false green this prevents.
        let patterns = [pattern("catch", "warning", Watched::Both)];
        let bytes = b"\xff\xfe progress\nwarning: real\n";
        assert_eq!(hits(&patterns, Stream::Stdout, bytes).len(), 1);
    }

    #[test]
    fn every_hit_is_reported_not_only_the_first() {
        let patterns = [pattern("warn", "warning", Watched::Both)];
        let found = hits(&patterns, Stream::Stdout, b"warning a\nok\nwarning b\n");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].line, 1);
        assert_eq!(found[1].line, 3);
    }

    #[test]
    fn a_reason_is_stated_once_per_pattern_not_once_per_hit() {
        let patterns = [pattern("warn", "warning", Watched::Both)];
        let found = hits(&patterns, Stream::Stdout, b"warning a\nwarning b\n");
        assert_eq!(found.len(), 2);
        assert_eq!(reasons(&patterns, &found).len(), 1);
    }

    #[test]
    fn a_reason_is_required_because_a_promoted_code_is_all_the_caller_gets() {
        let mut bad = pattern("p", "x", Watched::Both);
        bad.reason = "  ".to_owned();
        let err = validate(&[bad]).expect_err("an empty reason is refused");
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn an_empty_pattern_is_refused_because_it_would_match_every_run() {
        let mut bad = pattern("p", "", Watched::Both);
        bad.pattern = String::new();
        assert!(validate(&[bad]).is_err());
    }

    #[test]
    fn a_duplicate_id_is_refused() {
        let rows = [
            pattern("same", "a", Watched::Both),
            pattern("same", "b", Watched::Both),
        ];
        assert!(validate(&rows).is_err());
    }

    #[test]
    fn a_well_formed_table_is_accepted() {
        assert!(validate(&[pattern("p", "x", Watched::Both)]).is_ok());
        assert!(validate(&[]).is_ok());
    }
}
