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
//! This module replaces `mise-tasks/context-budget.sh`, deleted in the same change.
//! Two gates counting the same surface by different rules is the drift a policy
//! engine must not model, so the shell task's `hk` wiring moved onto this verb
//! rather than running beside it. Its optional line predicate came along as
//! [`BudgetSet::max_lines`] so the deletion orphaned nothing.
//!
//! # Sets are named by the consumer, and `check` is where they bite
//!
//! `[budget.<name>]` is a **map**: the set name belongs to the repository
//! declaring it, and an engine field called `instructions` would be a
//! consumer-specific identifier in `crates/batten` (non-negotiable rule 1).
//!
//! Every declared set is evaluated by `batten check` as a non-spawning read
//! gate, producing an ordinary [`Finding`] rather than a private verdict path.
//! That is what makes a budget subject to the same waivers, `-J` shape, exit
//! contract and findings store as every other gate — `policy budget` is the
//! introspection surface, never the enforcement one. A gate that only reported
//! when asked is a gate nobody runs.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::identity::{self, FindingKind, StoredIdentity};
use crate::rules::{Finding, glob_match, tree_files};
use crate::severity::RuleSeverity;

/// Bytes per estimated token. A convention-level constant, not a
/// literature-backed claim — see the module docs for why an approximation is the
/// right shape here.
const BYTES_PER_TOKEN: usize = 4;

/// The `[budget]` table: **named** file sets and what each may cost.
///
/// A map, not a struct with a field per set. The set name is the *consumer's*
/// — `[budget.instructions]` is this repository's name for its always-loaded
/// context, and an engine type carrying that name would be a consumer-specific
/// identifier in `crates/batten` (non-negotiable rule 1). A second consumer
/// budgeting a different surface declares `[budget.<their-name>]` and needs no
/// engine change; before this it needed a new field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(transparent)]
pub struct Budget(pub BTreeMap<String, BudgetSet>);

impl Budget {
    /// The declared sets, in name order — the fixed evaluation and report order.
    pub fn sets(&self) -> impl Iterator<Item = (&String, &BudgetSet)> {
        self.0.iter()
    }

    /// Whether the table declares nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One `[budget.<name>]` table.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetSet {
    /// The counted file set, as globs over repo-relative `/`-separated paths.
    /// Every entry must match at least one file — see the module docs. Defaulted
    /// because a set may count only `embedded` entries; the two being empty
    /// *together* is what `measure` refuses.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// The ceiling on estimated tokens over the whole set. The boundary is
    /// `<=`: exactly at budget passes.
    pub max_tokens: usize,
    /// The optional ceiling on loaded lines, the second predicate the shell gate
    /// this replaces carried. Absent means unenforced — a threshold nobody
    /// declared is not a threshold of zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lines: Option<usize>,
    /// Always-loaded strings carried *inside* a config file rather than in a
    /// file of their own. Empty by default: a repository with no such surface
    /// declares nothing (CLOUD-298).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub embedded: Vec<EmbeddedDecl>,
}

/// One `[[budget.<name>.embedded]]` entry: a string inside a config file that a
/// host loads on every session.
///
/// Both fields are the **consumer's**. A host that always injects a key from its
/// own config — Serena's project file, an editor's workspace settings — is a
/// property of the repository using that host, not of Batten, so naming either
/// one in `crates/batten` would be the consumer-specific identifier
/// non-negotiable rule 1 forbids. The engine knows only "parse this file, read
/// this key, count the string".
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedDecl {
    /// The repo-relative, `/`-separated path of the config file to read. A
    /// literal path and never a glob: a key is read from one document, and a
    /// pattern would leave "which file's key" unanswered.
    pub path: String,
    /// The key whose string value is counted. Dotted for a nested key
    /// (`a.b.c`); the engine walks maps only, so a key under a sequence is a
    /// miss rather than a guess.
    pub key: String,
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
    /// Which declared set this measures. The consumer's name, carried so a
    /// finding and a report row can say *which* budget was exceeded — with
    /// several sets declared, a count with no name is unactionable.
    pub name: String,
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
                "policy-budget {}: ~{} tokens of {}, {} lines of {max_lines}",
                self.name, self.tokens, self.max_tokens, self.lines
            ),
            None => format!(
                "policy-budget {}: ~{} tokens of {}, {} lines",
                self.name, self.tokens, self.max_tokens, self.lines
            ),
        }
    }

    /// The rule id a violation of this budget is reported under.
    ///
    /// Namespaced by the table it came from, so a budget finding is never
    /// mistaken for a `[[rule]]` row's and two consumers' set names cannot
    /// collide with a rule id.
    #[must_use]
    pub fn rule_id(&self) -> String {
        format!("budget.{}", self.name)
    }

    /// This report as a finding, when it is over either bound.
    ///
    /// A real [`Finding`], not a bespoke channel: budgets then flow through the
    /// one funnel `check` and `enforce` share — waivers, `-J`, the exit contract
    /// and the findings store — instead of growing a second verdict path that
    /// would have to re-implement each of them.
    ///
    /// [`FindingKind::Scope`] is the honest kind: a budget is a whole-repo
    /// condition, not a span in a file, and its identity is `(scope, rule_id,
    /// set name)` — stable across the content edits that move the count, which
    /// is what lets a store recognise the same over-budget finding twice.
    ///
    /// Pointer-only: the path is the set name and the counts are counts. No
    /// measured file's content reaches it (rule 4).
    #[must_use]
    pub fn finding(&self) -> Option<Finding> {
        if !self.over_budget() {
            return None;
        }
        let rule = self.rule_id();
        let identity = StoredIdentity::new(
            FindingKind::Scope,
            identity::scope_fingerprint(&rule, &self.name),
        );
        Some(Finding {
            owner: None,
            rule,
            severity: RuleSeverity::Deny,
            path: self.name.clone(),
            line: None,
            identity,
            // Engine-produced (no `[[rule]]` row): re-measuring the set is the
            // check, and the fix is cutting instructions — prose a command cannot
            // write.
            check: crate::findings::Check::Reevaluate,
            remediation: Some(crate::findings::Remediation::NoFix(
                "cut instruction text until the set is under its budget".to_owned(),
            )),
        })
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

/// The string an [`EmbeddedDecl`] points at, or `None` when the key is absent,
/// null, or not a string.
///
/// The parser is chosen by extension, which makes the rule **total**: every path
/// either names a format the engine reads or is refused. TOML and JSON cost
/// nothing — both parsers are already vendored for the config loader and the
/// data channel — so supporting all three is cheaper than justifying why only
/// one consumer's format is readable.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) naming the path when the extension is
/// unknown or the document does not parse. That refusal is the whole point: an
/// always-loaded surface the gate cannot read must never be reported as an empty
/// one, which is the same false green a dead glob produced (CLOUD-298).
fn embedded_value(root: &Path, name: &str, decl: &EmbeddedDecl) -> Result<Option<String>> {
    let full = root.join(&decl.path);
    let text = match fs::read_to_string(&full) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(UsageError::raise(format!(
                "budget.{name}: `{}` matches no file; a dead entry contributes nothing and must \
                 not pass as measured",
                decl.path
            )));
        }
        Err(error) => return Err(error.into()),
    };

    // Only the extension is trusted to name the format. Sniffing the content
    // would make an unparseable document look like a different format rather
    // than like the refusal it is.
    let extension = Path::new(&decl.path)
        .extension()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or_default();
    let keys: Vec<&str> = decl.key.split('.').collect();
    let unreadable = |what: &str| {
        UsageError::raise(format!(
            "budget.{name}: `{}` is not readable as {what}; an uncountable surface must not read \
             as an empty one",
            decl.path
        ))
    };

    match extension {
        "yml" | "yaml" => {
            let docs =
                yaml_rust2::YamlLoader::load_from_str(&text).map_err(|_| unreadable("YAML"))?;
            // An empty document declares no keys — the same answer as a key that
            // is simply absent, and not a parse failure.
            let Some(doc) = docs.first() else {
                return Ok(None);
            };
            let mut node = doc;
            for key in keys {
                node = &node[key];
            }
            Ok(node.as_str().map(ToOwned::to_owned))
        }
        "toml" => {
            let value: toml::Value = toml::from_str(&text).map_err(|_| unreadable("TOML"))?;
            let mut node = &value;
            for key in keys {
                match node.get(key) {
                    Some(next) => node = next,
                    None => return Ok(None),
                }
            }
            Ok(node.as_str().map(ToOwned::to_owned))
        }
        "json" => {
            let value: serde_json::Value =
                serde_json::from_str(&text).map_err(|_| unreadable("JSON"))?;
            let mut node = &value;
            for key in keys {
                match node.get(key) {
                    Some(next) => node = next,
                    None => return Ok(None),
                }
            }
            Ok(node.as_str().map(ToOwned::to_owned))
        }
        _ => Err(UsageError::raise(format!(
            "budget.{name}: `{}` has no format this gate can read (expected .yml, .yaml, .toml or \
             .json); an uncountable surface must not read as an empty one",
            decl.path
        ))),
    }
}

/// Estimated tokens over already-[`loaded`] content.
#[must_use]
pub fn estimate_tokens(loaded: &str) -> usize {
    loaded.len() / BYTES_PER_TOKEN
}

/// Estimated tokens over a byte count whose content is not held (CLOUD-417).
///
/// The same divisor as [`estimate_tokens`], reached from the other side: a
/// session transcript's size is known while its bytes deliberately are not, and
/// a second divisor invented at that call site would make hook cost and
/// instruction cost two incommensurable numbers over one window.
#[must_use]
pub fn estimate_tokens_over(bytes: usize) -> usize {
    bytes / BYTES_PER_TOKEN
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
pub fn measure(root: &Path, name: &str, budget: &BudgetSet) -> Result<Report> {
    if budget.files.is_empty() && budget.embedded.is_empty() {
        return Err(UsageError::raise(format!(
            "budget.{name}: neither `files` nor `embedded` declares an entry; a budget over \
             nothing is not a budget"
        )));
    }

    let tree = tree_files(root)?;
    // A set, so two entries selecting the same file count it once — a budget is
    // over the content an agent loads, and it loads that file once.
    let mut selected = BTreeSet::new();
    for entry in &budget.files {
        let mut matched = tree
            .iter()
            .filter(|path| glob_match(entry, path))
            .peekable();
        if matched.peek().is_none() {
            return Err(UsageError::raise(format!(
                "budget.{name}: `{entry}` matches no file; a dead entry contributes nothing and \
                 must not pass as measured"
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

    for decl in &budget.embedded {
        let Some(value) = embedded_value(root, name, decl)? else {
            // Absent, null, or empty contributes nothing AND adds no row: a zero
            // row would report a surface as measured-and-free when there is
            // nothing there to measure.
            continue;
        };
        let loaded = loaded(&value);
        if loaded.is_empty() {
            continue;
        }
        let file = FileCount {
            // `path#key` so the counted set stays discoverable from the report:
            // a surface that IS counted names itself, and one that is not cannot
            // hide behind the total.
            path: format!("{}#{}", decl.path, decl.key),
            tokens: estimate_tokens(&loaded),
            lines: count_lines(&loaded),
        };
        tokens += file.tokens;
        lines += file.lines;
        files.push(file);
    }

    // One sort over both kinds, so the report keeps its documented path order
    // whatever order the two loops produced.
    files.sort_by(|a, b| a.path.cmp(&b.path));

    Ok(Report {
        name: name.to_owned(),
        files,
        tokens,
        lines,
        max_tokens: budget.max_tokens,
        max_lines: budget.max_lines,
    })
}

/// Measure every declared set, in name order.
///
/// An absent `[budget]` table measures nothing and is **not** an error here:
/// this is the form `check` calls, and a repository that declares no budget has
/// no budget to fail. That is the opposite reading from `policy budget`, whose
/// whole job is to report a measurement — a budget verb with no budget measured
/// nothing, and saying `0` there would be the false green the engine exists to
/// catch. Same absence, two honest readings, because the two callers are asking
/// different questions.
///
/// # Errors
///
/// Propagates [`measure`]'s errors for any declared set.
pub fn measure_all(root: &Path, budget: Option<&Budget>) -> Result<Vec<Report>> {
    let Some(budget) = budget else {
        return Ok(Vec::new());
    };
    budget
        .sets()
        .map(|(name, set)| measure(root, name, set))
        .collect()
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
    if budget.is_empty() {
        return Err(UsageError::raise(
            "budget: the table declares no set; remove it or declare [budget.<name>]".to_owned(),
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
            name: "instructions".to_owned(),
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

    fn budget_of(name: &str) -> Budget {
        Budget(
            [(
                name.to_owned(),
                BudgetSet {
                    files: vec!["AGENTS.md".to_owned()],
                    max_tokens: 1,
                    max_lines: None,
                    embedded: Vec::new(),
                },
            )]
            .into_iter()
            .collect(),
        )
    }

    #[test]
    fn a_budget_table_declaring_no_budget_is_refused() {
        let err = validate(Some(&Budget(BTreeMap::new()))).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(validate(None).is_ok());
        assert!(validate(Some(&budget_of("instructions"))).is_ok());
    }

    #[test]
    fn a_set_name_is_the_consumers_and_the_engine_carries_none() {
        // Rule 1: the engine must hold no consumer-specific identifier. Any name
        // works, because the table is a map rather than a field per set — before
        // this, a second consumer's budget needed an engine change.
        for name in ["instructions", "prompts", "whatever-they-call-it"] {
            let budget = budget_of(name);
            assert!(validate(Some(&budget)).is_ok());
            let (declared, _) = budget.sets().next().unwrap();
            assert_eq!(declared, name);
        }
    }

    #[test]
    fn an_over_budget_report_is_an_ordinary_finding_naming_its_set() {
        // Budgets bite through `check` as a normal finding, which is what makes
        // them waivable and puts them in `-J` and the store for free.
        let within = Report {
            name: "instructions".to_owned(),
            files: Vec::new(),
            tokens: 10,
            lines: 1,
            max_tokens: 100,
            max_lines: None,
        };
        assert!(
            within.finding().is_none(),
            "a set within budget produces no finding"
        );

        let over = Report {
            tokens: 101,
            ..within.clone()
        };
        let finding = over.finding().expect("over budget produces a finding");
        assert_eq!(finding.rule, "budget.instructions");
        assert_eq!(finding.severity, RuleSeverity::Deny);
        assert_eq!(
            finding.path, "instructions",
            "the pointer is the set name, never a measured file's content"
        );
        assert_eq!(finding.line, None);

        // Identity is over the set, not the counts: the same over-budget set is
        // one finding across the edits that move the number.
        let worse = Report {
            tokens: 5_000,
            ..over.clone()
        };
        assert_eq!(
            worse.finding().unwrap().identity,
            finding.identity,
            "a bigger overrun is the same finding, not a new one"
        );

        // A different set is a different finding.
        let other = Report {
            name: "prompts".to_owned(),
            ..over
        };
        assert_ne!(other.finding().unwrap().identity, finding.identity);
    }

    #[test]
    fn measuring_no_declared_budget_is_empty_for_check_and_never_an_error() {
        // `check`'s reading of the absent table: a repository that declares no
        // budget has no budget to fail. `policy budget` reads the same absence
        // as a usage error, because a report that measured nothing must not
        // print `0` — two callers, two honest readings.
        assert!(measure_all(Path::new("."), None).unwrap().is_empty());
    }
}
