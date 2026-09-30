//! The `released` reading: which tracker rows a release tag shipped, and the two
//! facts that make shipping necessary but not sufficient for Done (CLOUD-174,
//! CLOUD-257, CLOUD-309), retired off `[tasks.released]`'s inline body under
//! CLOUD-843.
//!
//! # What retired into here, and what did not
//!
//! The body walked `git describe` and `git log` for the range, piped the payload
//! set through `jq` five times, ran `batten board check` as a child and grepped
//! its stderr for each id's rule. The walk is [`crate::git`]'s, in process; the
//! payload set is [`crate::board_check::payload_set`]'s one parse; and the board
//! gate is COMPOSED in process through [`crate::board_check::graph_findings`] —
//! its verdict forwarded, never its predicate copied, so no pull-request
//! spelling appears here. Every DECISION over the record — that a held or a
//! refused row in the review column must not move, and that a dangling blocker
//! is a property of the piped set rather than a refusal — is the
//! `tracker-hygiene` preset's `shipping-is-not-sufficient` module.
//!
//! # Repo-agnostic by construction (non-negotiable rule 1)
//!
//! The issue key is the consumer's `ready-issue-key` row through
//! [`crate::ready::Grammar`]; the hold marker a `[[pattern]]` row the caller
//! names; the review column `[board] review`. None is a literal here.
//!
//! # Could-not-look writes nothing
//!
//! A tag that does not exist, a set that is not payloads, a review-column
//! payload missing a key the board gate decides on — PRESENCE, never truthiness
//! — and a board gate that could not run are each a [`UsageError`], and the
//! caller has cleared the family first, so the store holds this answer or none.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Result;
use regex::Regex;
use serde_json::Value;

use crate::board::Board;
use crate::error::UsageError;
use crate::pattern::NamedPattern;
use crate::ready::Grammar;

/// The record family this module writes, and the key the module reads.
pub const FAMILY: &str = "released";

//MUTANT-SUITE crates/batten/tests/it/released.rs
//MUTANT attachments-absence-is-silent|s@^    ("attachments", .*$@@|an_in_review_payload_with_no_attachments_key_is_could_not_look
//MUTANT description-absence-is-silent|s@^    ("description", .*$@@|an_in_review_payload_with_no_description_is_refused_and_named
//MUTANT relations-absence-is-silent|s@^    ("relations", .*$@@|an_in_review_payload_with_no_relations_is_refused_and_named

/// The keys a review-column payload must CARRY for the board gate to answer
/// about it, each with the re-fetch that supplies it (CLOUD-783).
///
/// Checked here because the gate keys these absences to its `graph` pseudo-id,
/// which no per-row lookup matches: a payload without one would read as a row
/// nothing refused. One key per line, so a `#MUTANT` row can drop exactly one.
const REVIEW_KEYS: &[(&str, &str)] = &[
    ("attachments", "re-fetch with attachments included"),
    ("description", "re-fetch with the description included"),
    ("relations", "re-fetch with `includeRelations: true`"),
];

/// A could-not-look refusal, worded once.
fn refuse(why: &str) -> anyhow::Error {
    UsageError::raise(format!("record derive {FAMILY}: {why}. Nothing recorded."))
}

/// The composed board gate did not answer — never an empty report.
fn could_not_run(why: anyhow::Error) -> anyhow::Error {
    refuse(&format!(
        "batten board check could not run ({why}); a gate that cannot run is not a pass"
    ))
}

/// Refuse an input key this reading does not take.
fn only(inputs: &BTreeMap<String, String>) -> Result<()> {
    match inputs
        .keys()
        .find(|key| !["tag", "hold"].contains(&key.as_str()))
    {
        Some(key) => Err(refuse(&format!("reads no input `{key}`"))),
        None => Ok(()),
    }
}

/// A JSON value as `jq -r` renders it: a string bare, anything else as JSON.
fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// One payload's `id`, or `None` where it carries none.
fn id_of(issue: &Value) -> Option<String> {
    issue.get("id").map(text_of).filter(|id| !id.is_empty())
}

/// The digits after an id's first `-`, for a byte-stable numeric order.
fn ordinal(id: &str) -> u64 {
    id.split_once('-')
        .map(|(_, rest)| {
            rest.chars()
                .take_while(char::is_ascii_digit)
                .collect::<String>()
        })
        .and_then(|digits| digits.parse().ok())
        .unwrap_or(0)
}

/// The rule a board-gate pointer line names for `id`: the leading `[a-z-]` run
/// of the word after it, or `None` where the line is another row's.
fn rule_for(line: &str, id: &str) -> Option<String> {
    let rest = line.strip_prefix(id)?.strip_prefix(' ')?;
    let rule: String = rest
        .chars()
        .take_while(|c| c.is_ascii_lowercase() || *c == '-')
        .collect();
    (!rule.is_empty()).then_some(rule)
}

/// The `released` record: the tag's range, every row it shipped, and for each
/// shipped row the caller piped, its column, its hold and every rule the board
/// gate raised for it.
///
/// Inputs: `tag`, the release tag, and `hold`, the `[[pattern]]` row naming the
/// marker a row puts in its own description to hold itself open. Stdin is the
/// payload set, or nothing: an empty stdin records what the tag shipped and
/// judges no row, which is clean — a pure-chore release ships no issue.
///
/// ```text
/// range     <prev>..<tag> | <tag>
/// shipped   <id>
/// issue     <id> <review|other> <held|free>
/// refusal   <id> <rule>
/// census    issues=<n>
/// ```
///
/// # Errors
///
/// A [`UsageError`] for each could-not-look this module's header names.
//MUTANT earlier-tag-reshipped|s@^    let hidden: Vec<String> = previous.iter().cloned().collect();$@    let hidden: Vec<String> = Vec::new();@|a_commit_an_earlier_tag_shipped_is_not_new
//MUTANT unrun-gate-passes|s@^        Err(why) => return Err(could_not_run(why)),$@        Err(_) => Vec::new(),@|a_board_check_that_did_not_run_is_could_not_look
//MUTANT commit-path-dropped|s@^            by_commit.insert(id);$@            let _ = id;@|a_commit_the_tag_contains_is_a_second_way_in
pub fn reading(
    inputs: &BTreeMap<String, String>,
    board: Option<&Board>,
    patterns: &[NamedPattern],
    root: &Path,
    stdin: &str,
) -> Result<String> {
    only(inputs)?;
    let tag = inputs
        .get("tag")
        .map(String::as_str)
        .filter(|tag| !tag.is_empty())
        .ok_or_else(|| refuse("needs `--input tag=<release tag>`"))?;
    let hold = held_by(patterns, inputs)?;
    let tip = format!("refs/tags/{tag}");
    if crate::git::resolve_ref(root, &tip)?.is_none() {
        return Err(refuse(&format!(
            "no such tag: {tag}. A tag that does not exist is a caller error, not an empty release"
        )));
    }
    let grammar = Grammar::resolve(patterns)?;
    let previous = crate::git::previous_tag(root, tag)?;
    let range = previous
        .as_deref()
        .map_or_else(|| tag.to_owned(), |prev| format!("{prev}..{tag}"));
    let hidden: Vec<String> = previous.iter().cloned().collect();
    let tips = [tip];
    let messages = crate::git::messages_reachable(root, &tips, &hidden)?;
    let commits = crate::git::commits_reachable(root, &tips, &hidden)?;
    let mut shipped: BTreeSet<(u64, String)> = grammar
        .keys_in(&messages)
        .into_iter()
        .map(|key| key.to_string())
        .map(|key| (ordinal(&key), key))
        .collect();

    let mut record = String::new();
    writeln!(record, "range\t{range}")?;
    if stdin.trim().is_empty() {
        for (_, id) in &shipped {
            writeln!(record, "shipped\t{id}")?;
        }
        writeln!(record, "census\tissues=0")?;
        return Ok(record);
    }

    let set = crate::board_check::payload_set(stdin)
        .filter(|set| {
            set.iter()
                .all(|issue| issue.get("id").is_some() && issue.get("status").is_some())
        })
        .ok_or_else(|| {
            refuse("stdin is not a set of get_issue payloads (need id and status per issue)")
        })?;
    let review = board
        .and_then(|board| board.review.as_deref())
        .ok_or_else(|| {
            refuse("`board.review` is not declared, so no row can be read as In Review")
        })?;
    let in_review = |issue: &&Value| issue.get("status").map(text_of).as_deref() == Some(review);
    for (key, remedy) in REVIEW_KEYS {
        let missing: Vec<String> = set
            .iter()
            .filter(in_review)
            .filter(|issue| issue.get(key).is_none())
            .filter_map(id_of)
            .collect();
        if !missing.is_empty() {
            return Err(refuse(&format!(
                "no `{key}` on In Review issue(s): {}. The board gate reads that key, so a \
                 payload without it cannot answer — {remedy}",
                missing.join(" ")
            )));
        }
    }
    let declared = crate::board_check::Declared {
        board,
        patterns,
        grammar: &grammar,
        root,
    };
    let findings = match crate::board_check::graph_findings(&set, &declared) {
        Ok(findings) => findings,
        Err(why) => return Err(could_not_run(why)),
    };

    // THE SECOND WAY IN (CLOUD-260): a payload's `commit`, for work that landed
    // before every change carried its key. A sha that does not resolve is
    // supplementary evidence ignored, never fatal.
    let mut by_commit: BTreeSet<String> = BTreeSet::new();
    for issue in &set {
        let (Some(id), Some(sha)) = (id_of(issue), issue.get("commit").map(text_of)) else {
            continue;
        };
        if sha.is_empty() || sha == "null" {
            continue;
        }
        let resolved = crate::git::resolve_ref(root, &format!("{sha}^{{commit}}"))
            .ok()
            .flatten();
        if resolved.is_some_and(|full| commits.contains(&full)) {
            by_commit.insert(id);
        }
    }
    shipped.extend(by_commit.into_iter().map(|id| (ordinal(&id), id)));

    let mut judged = 0usize;
    let mut rows = String::new();
    for (_, id) in &shipped {
        writeln!(record, "shipped\t{id}")?;
        // Shipped but not piped is not a finding: the caller chose the closure.
        let Some(issue) = set.iter().find(|issue| id_of(issue).as_deref() == Some(id)) else {
            continue;
        };
        let column = if in_review(&issue) { "review" } else { "other" };
        let body = issue.get("description").map(text_of).unwrap_or_default();
        let held = if hold.is_match(&body) { "held" } else { "free" };
        writeln!(rows, "issue\t{id}\t{column}\t{held}")?;
        judged += 1;
        for rule in findings.iter().filter_map(|line| rule_for(line, id)) {
            writeln!(rows, "refusal\t{id}\t{rule}")?;
        }
    }
    record.push_str(&rows);
    writeln!(record, "census\tissues={judged}")?;
    Ok(record)
}

/// The hold marker's declared row, compiled.
fn held_by(patterns: &[NamedPattern], inputs: &BTreeMap<String, String>) -> Result<Regex> {
    let id = inputs
        .get("hold")
        .ok_or_else(|| refuse("needs `--input hold=<[[pattern]] row>`"))?;
    let row = patterns
        .iter()
        .find(|row| &row.id == id)
        .ok_or_else(|| refuse(&format!("no `[[pattern]]` row declares `{id}`")))?;
    Regex::new(&row.regex)
        .map_err(|_| refuse(&format!("`[[pattern]]` row `{id}` will not compile")))
}

#[cfg(test)]
mod tests {
    use super::{ordinal, rule_for};

    #[test]
    fn a_pointer_line_names_its_own_rows_rule_only() {
        assert_eq!(
            rule_for("A-2 in-review-no-pr", "A-2").as_deref(),
            Some("in-review-no-pr")
        );
        assert_eq!(rule_for("A-22 in-review-no-pr", "A-2"), None);
        assert_eq!(rule_for("graph dangling-blocker (A-9)", "A-2"), None);
        assert_eq!(
            rule_for("A-2 excluded (unjudgeable-blocker A-9)", "A-2").as_deref(),
            Some("excluded")
        );
    }

    #[test]
    fn keys_order_by_their_number() {
        assert!(ordinal("A-9") < ordinal("A-10"));
        assert_eq!(ordinal("no-digits"), 0);
    }
}
