//! The instruction-set token budget (CLOUD-50) — `batten policy budget`.
//!
//! An always-loaded instruction file is not a style question, it is a per-turn
//! tax: every agent pays its tokens on every turn whether or not a word of it
//! applies. A memory read at a trigger is the release valve, and moving a
//! section into one is a real reduction only if the destination is *not* itself
//! always loaded — which is why anything always-loaded is counted together, as
//! one set, against one budget.
//!
//! ## Why an estimate, and why this estimate
//!
//! Tokens are estimated at [`BYTES_PER_TOKEN`] bytes per token over the content
//! that actually loads. That is an approximation on purpose. An exact count
//! needs a tokenizer, a model-specific vocabulary, and in practice a network
//! fetch — and a budget gate that can fail because a download failed is worse
//! than one that is ten percent out. The estimate is **stable, offline and
//! monotone**, which is all a budget needs, and monotonicity is what makes the
//! predicate decidable in the house-style §0.3 sense: a count against a constant
//! guard.
//!
//! "The content that actually loads" is load-bearing rather than fussy.
//! [`loaded`] strips YAML frontmatter and block-level HTML comments before
//! counting, because a host strips both before the file reaches a context
//! window. Counting raw bytes would tax the one construct that is already free,
//! so the gate could fail for a construct no agent pays for — a failure
//! unrelated to the content it claims to measure.
//!
//! ## A dead entry is an error, never a pass
//!
//! [`measure`] resolves each configured entry **on its own**. An entry matching
//! no file raises a [`UsageError`] (→ exit `1`) naming that entry, even when its
//! siblings match. The whole-set reading is what let one glob quietly contribute
//! nothing while the rest counted, and a budget that silently measures less than
//! it claims is a green that means nothing (CLOUD-298).
//!
//! ## Succession
//!
//! This module replaces `mise-tasks/context-budget`, deleted in the same change.
//! Two gates counting the same surface by different rules is the drift a policy
//! engine must not model, so the shell task's `hk` wiring moved onto this verb
//! rather than running beside it. Its optional line predicate came along as
//! [`InstructionBudget::max_lines`] so the deletion orphaned nothing.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::{glob_match, tree_files};

/// Bytes per estimated token. A convention-level constant, not a
/// literature-backed claim — see the module docs for why an approximation is the
/// right shape here.
const BYTES_PER_TOKEN: usize = 4;

/// The `[budget]` table: thresholds this repository holds itself to.
///
/// One field today. A future budget over a different surface — the advisory
/// drain's, say (CLOUD-82) — is a sibling key here, not a second meaning loaded
/// onto this one; the two share the estimator's discipline and nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// The always-loaded instruction set and what it may cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instructions: Option<InstructionBudget>,
}

/// The `[budget.instructions]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct InstructionBudget {
    /// The instruction-file set, as globs over repo-relative `/`-separated
    /// paths. Every entry must match at least one file — see the module docs.
    pub paths: Vec<String>,
    /// The ceiling on estimated tokens over the whole set. The boundary is
    /// `<=`: exactly at budget passes.
    pub max_tokens: usize,
    /// The optional ceiling on loaded lines, the second predicate the shell gate
    /// this replaces carried. Absent means unenforced — a threshold nobody
    /// declared is not a threshold of zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lines: Option<usize>,
}

/// One measured file. Pointer-only: a path and two counts, never a byte of the
/// content that produced them (non-negotiable rule 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct FileCount {
    /// The repo-relative path, `/`-separated.
    pub path: String,
    /// Estimated tokens over the loaded content.
    pub tokens: usize,
    /// Lines of loaded content.
    pub lines: usize,
}

/// What [`measure`] found: the per-file counts, the totals, and the budgets they
/// were judged against.
///
/// Byte-stable for identical input — files are reported in sorted path order and
/// no field derives from the clock, the environment, or where the repository
/// lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Report {
    /// The measured files, sorted by path.
    pub files: Vec<FileCount>,
    /// Estimated tokens over the whole set.
    pub tokens: usize,
    /// Loaded lines over the whole set.
    pub lines: usize,
    /// The token ceiling this run was judged against.
    pub max_tokens: usize,
    /// The line ceiling, when one is configured.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_lines: Option<usize>,
}

impl Report {
    /// Whether either predicate failed.
    ///
    /// Both boundaries are `<=`, so exactly at budget passes. The line predicate
    /// is skipped entirely when no ceiling is configured — an absent key is not
    /// a ceiling of zero.
    #[must_use]
    pub fn over_budget(&self) -> bool {
        self.tokens > self.max_tokens || self.max_lines.is_some_and(|max| self.lines > max)
    }

    /// The one-line summary: the totals and the budgets they were judged
    /// against. Counts only.
    #[must_use]
    pub fn summary(&self) -> String {
        match self.max_lines {
            Some(max_lines) => format!(
                "policy-budget: ~{} tokens of {}, {} lines of {max_lines}",
                self.tokens, self.max_tokens, self.lines
            ),
            None => format!(
                "policy-budget: ~{} tokens of {}, {} lines",
                self.tokens, self.max_tokens, self.lines
            ),
        }
    }
}

impl FileCount {
    /// The per-file report line: a pointer and its counts.
    #[must_use]
    pub fn line(&self) -> String {
        format!("{} ~{} tokens {} lines", self.path, self.tokens, self.lines)
    }
}

/// The content of `text` that actually reaches a context window: YAML
/// frontmatter and block-level HTML comments removed.
///
/// Both constructs are dropped by the loader before injection, so both are free
/// and neither may be taxed here. Frontmatter is recognised only as a leading
/// `---` fence, and a comment only where it opens at the start of a line —
/// the same two shapes the shell gate this replaces recognised, so the
/// succession changes the *mechanism* and not the measured surface.
///
/// Implemented as a byte scan rather than a pattern match: the crate carries no
/// regex dependency by design, and `outputs.rs` sets the precedent that a
/// literal is enough.
#[must_use]
pub fn loaded(text: &str) -> String {
    strip_comments(strip_frontmatter(text))
}

/// Drop a leading `---\n … \n---\n` frontmatter fence, if there is one.
fn strip_frontmatter(text: &str) -> &str {
    let Some(rest) = text.strip_prefix("---\n") else {
        return text;
    };
    // The closing fence is a `---` on its own line. Without one the document has
    // no frontmatter, only a horizontal rule — leave it alone rather than
    // guessing where it ends.
    match rest.find("\n---\n") {
        Some(end) => &rest[end + "\n---\n".len()..],
        None => text,
    }
}

/// Drop every block-level HTML comment: one opening at the start of a line,
/// through its first `-->` and the newline that follows it.
///
/// Line-anchored on purpose. An inline `<!-- … -->` inside a sentence is part of
/// the prose around it, and removing it would change the measured content in a
/// way the loader does not.
fn strip_comments(text: &str) -> String {
    const OPEN: &str = "<!--";
    const CLOSE: &str = "-->";

    let mut kept = String::with_capacity(text.len());
    let mut rest = text;
    loop {
        let Some(open) = find_line_anchored(rest, OPEN) else {
            kept.push_str(rest);
            return kept;
        };
        let Some(close) = rest[open..].find(CLOSE) else {
            // An unterminated comment is not a comment; the loader would inject
            // it verbatim, so it is counted verbatim.
            kept.push_str(rest);
            return kept;
        };
        kept.push_str(&rest[..open]);
        let mut after = open + close + CLOSE.len();
        if rest[after..].starts_with('\n') {
            after += 1;
        }
        rest = &rest[after..];
    }
}

/// The byte offset of the first `needle` that begins at the start of a line.
fn find_line_anchored(haystack: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(hit) = haystack[from..].find(needle) {
        let at = from + hit;
        if at == 0 || haystack.as_bytes()[at - 1] == b'\n' {
            return Some(at);
        }
        from = at + needle.len();
    }
    None
}

/// Estimated tokens over already-[`loaded`] content.
#[must_use]
pub fn estimate_tokens(loaded: &str) -> usize {
    loaded.len() / BYTES_PER_TOKEN
}

/// Lines of already-[`loaded`] content.
///
/// A final line with no trailing newline still counts: it is content an agent
/// reads.
#[must_use]
pub fn count_lines(loaded: &str) -> usize {
    loaded.lines().count()
}

/// Measure the configured instruction set under `root`.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the configured set is empty, or
/// when any single entry matches no file — per entry, never per set, so a dead
/// glob cannot hide behind the entries that still count. An I/O failure while
/// walking or reading propagates as an internal error (→ exit `3`).
pub fn measure(root: &Path, budget: &InstructionBudget) -> Result<Report> {
    if budget.paths.is_empty() {
        return Err(UsageError::raise(
            "budget.instructions: `paths` declares no entries; a budget over nothing is not a \
             budget"
                .to_owned(),
        ));
    }

    let tree = tree_files(root)?;
    // A set, so two entries selecting the same file count it once — a budget is
    // over the content an agent loads, and it loads that file once.
    let mut selected = BTreeSet::new();
    for entry in &budget.paths {
        let mut matched = tree
            .iter()
            .filter(|path| glob_match(entry, path))
            .peekable();
        if matched.peek().is_none() {
            return Err(UsageError::raise(format!(
                "budget.instructions: `{entry}` matches no file; a dead entry contributes nothing \
                 and must not pass as measured"
            )));
        }
        selected.extend(matched.cloned());
    }

    let mut files = Vec::with_capacity(selected.len());
    let mut tokens = 0;
    let mut lines = 0;
    // `BTreeSet` iterates in sorted order, which is the fixed reporting order.
    for path in selected {
        let text = fs::read_to_string(root.join(&path))?;
        let loaded = loaded(&text);
        let file = FileCount {
            path,
            tokens: estimate_tokens(&loaded),
            lines: count_lines(&loaded),
        };
        tokens += file.tokens;
        lines += file.lines;
        files.push(file);
    }

    Ok(Report {
        files,
        tokens,
        lines,
        max_tokens: budget.max_tokens,
        max_lines: budget.max_lines,
    })
}

/// Validate the `[budget]` table at load.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a `[budget]` table declaring no
/// budget. A table that parses and gates nothing is the half-change
/// non-negotiable rule 2 exists to refuse.
pub fn validate(budget: Option<&Budget>) -> Result<()> {
    let Some(budget) = budget else {
        return Ok(());
    };
    if budget.instructions.is_none() {
        return Err(UsageError::raise(
            "budget: the table declares no budget; remove it or declare \
             [budget.instructions]"
                .to_owned(),
        ));
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn frontmatter_is_stripped_only_as_a_leading_fence() {
        assert_eq!(loaded("---\nname: x\n---\nbody\n"), "body\n");
        // A `---` that is not leading is a horizontal rule, and costs what it
        // costs.
        assert_eq!(
            loaded("body\n---\nname: x\n---\n"),
            "body\n---\nname: x\n---\n"
        );
        // An unterminated fence is not frontmatter.
        assert_eq!(loaded("---\nname: x\n"), "---\nname: x\n");
    }

    #[test]
    fn a_block_comment_is_free_and_an_inline_one_is_not() {
        assert_eq!(loaded("a\n<!-- note -->\nb\n"), "a\nb\n");
        assert_eq!(loaded("<!--\nmulti\nline\n-->\nb\n"), "b\n");
        // Inline: part of the prose around it, so it is counted.
        let inline = "text <!-- note --> more\n";
        assert_eq!(loaded(inline), inline);
    }

    #[test]
    fn an_unterminated_comment_is_counted_verbatim() {
        // The loader would inject it, so the gate must charge for it.
        let text = "a\n<!-- never closed\nb\n";
        assert_eq!(loaded(text), text);
    }

    #[test]
    fn the_estimate_is_monotone_in_loaded_bytes() {
        let short = estimate_tokens("12345678");
        let long = estimate_tokens("123456789012");
        assert!(
            short < long,
            "more loaded bytes must never estimate fewer tokens"
        );
        assert_eq!(short, 2);
        assert_eq!(long, 3);
    }

    #[test]
    fn stripped_constructs_cost_nothing() {
        let padded = format!("<!--\n{}\n-->\nkept\n", "x".repeat(10_000));
        assert_eq!(estimate_tokens(&loaded(&padded)), estimate_tokens("kept\n"));
    }

    #[test]
    fn a_final_line_without_a_newline_still_counts() {
        assert_eq!(count_lines("a\nb\nc"), 3);
        assert_eq!(count_lines("a\nb\nc\n"), 3);
        assert_eq!(count_lines(""), 0);
    }

    #[test]
    fn the_boundary_is_less_than_or_equal() {
        let at = Report {
            files: Vec::new(),
            tokens: 100,
            lines: 10,
            max_tokens: 100,
            max_lines: Some(10),
        };
        assert!(!at.over_budget(), "exactly at budget is within budget");

        let over_tokens = Report {
            tokens: 101,
            ..at.clone()
        };
        assert!(over_tokens.over_budget());

        let over_lines = Report {
            lines: 11,
            ..at.clone()
        };
        assert!(over_lines.over_budget());

        // An absent line ceiling is unenforced, not a ceiling of zero.
        let unenforced = Report {
            lines: 10_000,
            max_lines: None,
            ..at
        };
        assert!(!unenforced.over_budget());
    }

    #[test]
    fn a_budget_table_declaring_no_budget_is_refused() {
        let err = validate(Some(&Budget { instructions: None })).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(validate(None).is_ok());
        assert!(
            validate(Some(&Budget {
                instructions: Some(InstructionBudget {
                    paths: vec!["AGENTS.md".to_owned()],
                    max_tokens: 1,
                    max_lines: None,
                }),
            }))
            .is_ok()
        );
    }
}
