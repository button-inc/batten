//! The append-only defect ledger (CLOUD-52).
//!
//! This repository's discipline is that a defect becomes a mechanism — half its
//! gates cite the defect that forced them. Until now that record lived only in a
//! tracker, where nothing in a checkout can query it, no gate can validate it,
//! and no rule can cite it as data.
//!
//! # Not the findings store, deliberately
//!
//! [`crate::findings`] is the **signal** layer: machine-emitted, identity-hashed,
//! self-clearing, dispositioned, out of tree, drained to agents. This is the
//! **lesson** layer: curated (every row arrives through `defects add`),
//! permanent, taxonomy-classified, committed, and reviewed in a pull request. A
//! finding may cite a defect id; a defect names the rule that now gates it.
//!
//! Neither store can absorb the other without losing something: fold lessons
//! into findings and they self-clear, which is the one thing a lesson must never
//! do; fold findings into lessons and every scan needs review.
//!
//! # In tree, because that is what makes it reviewable
//!
//! House style §10 asks the defect log to survive a warm-fork restart, which a
//! committed file does trivially — "out of process" means outside the agent's
//! context, not outside the repository. Out-of-tree placement beside the findings
//! store would put it where nothing diffs it in review and no repo gate can
//! refuse a rewrite.
//!
//! # Append-only is a byte prefix, not a growing id set
//!
//! The predicate is that the ledger at its git base is a **byte prefix** of the
//! working-tree ledger. That is deliberately stronger than "no id disappeared":
//! it freezes the bytes of every past row, so a correction is a new row carrying
//! `supersedes`, never an edit to the row it corrects. An id-set check would let
//! a row's evidence be rewritten while its id stayed put, which is exactly the
//! quiet revision this ledger exists to make impossible.
//!
//! A ledger that shrank, or whose first divergent line differs, is a finding at
//! that `path:line`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::identity::{FindingKind, StoredIdentity};
use crate::rules::Finding;
use crate::severity::RuleSeverity;

/// The `[defects]` table: where the ledger lives and what may be in it.
///
/// Both keys are consumer facts. The crate carries neither a path nor a class
/// token (non-negotiable rule 1) — a taxonomy is a description of one team's
/// failure modes, not an engine fact.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Defects {
    /// The repo-relative path of the one JSONL ledger.
    pub path: String,
    /// The allowed `class` tokens. A record outside this set is refused.
    pub classes: Vec<String>,
}

impl Defects {
    /// Validate the table at load.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty path or an empty or
    /// duplicated taxonomy. An empty `classes` would refuse every record, which
    /// is a table that cannot be used rather than one that permits nothing.
    pub fn validate(&self) -> Result<()> {
        if self.path.trim().is_empty() {
            return Err(UsageError::raise(
                "defects.path: names no file; a ledger with no path is not a ledger".to_owned(),
            ));
        }
        if self.classes.is_empty() {
            return Err(UsageError::raise(
                "defects.classes: declares no class; every record would be refused, which is a \
                 table that cannot be used rather than one that permits nothing"
                    .to_owned(),
            ));
        }
        let unique: BTreeSet<&String> = self.classes.iter().collect();
        if unique.len() != self.classes.len() {
            return Err(UsageError::raise(
                "defects.classes: contains a duplicate".to_owned(),
            ));
        }
        Ok(())
    }
}

/// One defect record — the schema, defined once.
///
/// Every field is a pointer or an identifier. `evidence` is where the temptation
/// to paste sits, and it is documented as a pointer for the same reason every
/// other emission in this engine is one (rule 4): a ledger is committed and
/// permanent, so a secret pasted into it is a secret that cannot be expunged.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// A stable, unique identifier for this defect.
    pub id: String,
    /// The taxonomy class. Must be one the config declares.
    pub class: String,
    /// When it was observed, as a date the consumer writes.
    pub observed: String,
    /// Where the evidence is: `path:line`, a sha, or a URL. **A pointer, never
    /// pasted content** — this file is committed and permanent.
    pub evidence: String,
    /// The rule or gate id that now discharges the lesson.
    ///
    /// Absent is a legitimate, honest state: a lesson nobody has gated yet. That
    /// is the point of recording it — `defects query --ungated` enumerates
    /// exactly the rows that are still prose, which is the list rule 2 wants
    /// somebody looking at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement: Option<String>,
    /// The id this record corrects.
    ///
    /// Corrections append. There is no edit path, because the append-only gate
    /// makes one impossible — which is what keeps the ledger's history true
    /// rather than merely current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<String>,
}

impl Record {
    /// The canonical single-line JSON this record is stored as.
    ///
    /// One spelling, used by both the writer and the idempotence comparison, so
    /// "the same record" cannot mean two different byte strings.
    ///
    /// # Errors
    ///
    /// Serialization of this type cannot practically fail; the `Result` is the
    /// honest signature for a serde boundary.
    pub fn line(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// Parse a JSONL ledger, or the 1-based line of the first row that does not.
///
/// The line number rather than the serde error is the whole return value on the
/// failing side, because the gate reports a **pointer** and a serde message
/// quotes the offending bytes back (rule 4). [`parse`] wraps the same line
/// number into the usage error the verbs raise; neither spelling carries a byte
/// of the row.
fn parse_lines(text: &str) -> Result<Vec<Record>, usize> {
    let mut records = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let record: Record = serde_json::from_str(line).map_err(|_| index + 1)?;
        records.push(record);
    }
    Ok(records)
}

/// Parse a JSONL ledger, reporting the 1-based line of the first bad row.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) naming the line for any row that does
/// not parse. Blank lines are skipped: a trailing newline is not a record.
pub fn parse(text: &str) -> Result<Vec<Record>> {
    parse_lines(text).map_err(|line| {
        UsageError::raise(format!("defects: line {line} does not parse as a record"))
    })
}

/// A problem the ledger gate found, as a pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    /// The 1-based line it sits on.
    pub line: usize,
    /// The stable gate-finding id.
    pub id: &'static str,
}

/// A row whose `class` is not in the declared taxonomy.
pub const UNKNOWN_CLASS: &str = "defect-unknown-class";
/// A row whose id another row already used.
pub const DUPLICATE_ID: &str = "defect-duplicate-id";
/// A row that rewrites or removes history.
pub const NOT_APPEND_ONLY: &str = "defect-not-append-only";
/// A row that is not valid JSON for a [`Record`].
pub const MALFORMED_LINE: &str = "defect-malformed-line";

/// Every problem id the ledger gate can emit.
///
/// The census the repo's totality idiom walks: a new [`Problem`] variant that
/// does not appear here fails `every_ledger_problem_is_reachable`, which is what
/// keeps the taxonomy of gate findings from growing a member nothing exercises.
pub const PROBLEMS: &[&str] = &[MALFORMED_LINE, UNKNOWN_CLASS, DUPLICATE_ID, NOT_APPEND_ONLY];

impl Problem {
    /// This problem as an ordinary [`Finding`] against `path`.
    ///
    /// A real finding rather than a bespoke channel, for [`crate::budget`]'s
    /// reason: waivers, `-J`, the exit contract and the findings store all come
    /// free from being one, and a private verdict path would re-implement each.
    ///
    /// [`FindingKind::Scope`] with the **problem id** as the scope key, not the
    /// line: a row's line moves whenever a neighbour is appended, and a ledger
    /// is a file that only ever grows, so a position-keyed identity would mint a
    /// new one on every unrelated append. The line still rides the finding as
    /// its pointer.
    #[must_use]
    pub fn finding(&self, path: &str) -> Finding {
        let rule = self.id.to_owned();
        let identity = StoredIdentity::new(
            FindingKind::Scope,
            crate::identity::scope_fingerprint(&rule, path),
        );
        Finding {
            rule,
            severity: RuleSeverity::Deny,
            path: path.to_owned(),
            line: Some(self.line),
            identity,
            // Engine-produced, so there is no `[[rule]]` row to read these from.
            // Re-reading the ledger is the check; the fix is editing the row this
            // points at, which is a human judgement rather than an argv.
            check: crate::findings::Check::Reevaluate,
            remediation: Some(crate::findings::Remediation::NoFix(
                "resolve or rewrite the ledger row this points at".to_owned(),
            )),
        }
    }
}

/// The revisions the append-only half compares against.
///
/// `HEAD` plus the remote's recorded default branch when both resolve. **Two
/// bases, not one**, because either alone has a hole: `HEAD` alone passes a
/// branch that rewrote a row and committed it, and the remote default alone
/// passes a working tree that rewrote a row the branch already committed.
///
/// An unresolvable base is **dropped, never fatal, and never a pass on its own**
/// — a shallow clone with no remote HEAD still gets the `HEAD` comparison. The
/// case where neither resolves is a repository with no commits, where there is
/// no history to preserve and every row is genuinely an append.
fn bases(repo: &Path) -> Result<Vec<String>> {
    let mut bases = Vec::new();
    if crate::git::resolve_ref(repo, "HEAD")?.is_some() {
        bases.push("HEAD".to_owned());
    }
    if let Some(reference) = crate::git::remote_default_branch(repo)? {
        bases.push(reference);
    }
    Ok(bases)
}

/// The built-in ledger gate: every row parses, ids are unique, classes are in
/// the taxonomy, and the ledger is append-only against its git bases.
///
/// Active whenever `[defects]` is declared — the protected-path pattern, config
/// keys plus engine rather than a `[[rule]]` row. A consumer cannot lower it by
/// editing a rule table, which is the point: the ledger records the lessons that
/// produced the other gates, so a ledger a branch may quietly rewrite is worth
/// less than no ledger at all.
///
/// An **absent ledger file is silent**. `[defects]` declared before the first
/// record is the ordinary bootstrap state, and there is nothing there to be
/// wrong about.
///
/// # Errors
///
/// Returns an error only when git itself cannot be run. A malformed ledger is a
/// finding here, not a usage error: `check` must be able to report it beside
/// everything else it found rather than aborting the whole run on one bad row.
pub fn gate(repo: &Path, declared: &Defects) -> Result<Vec<Finding>> {
    let working = std::fs::read_to_string(repo.join(&declared.path)).unwrap_or_default();

    let mut problems = match parse_lines(&working) {
        Ok(records) => validate_records(&records, &declared.classes),
        // A row that does not parse stops the *content* checks — uniqueness and
        // taxonomy membership are questions about records and there are none —
        // but not the byte comparison below, which needs no parse. A ledger that
        // was both rewritten and malformed must not have the rewrite hidden by
        // the malformation.
        Err(line) => vec![Problem {
            line,
            id: MALFORMED_LINE,
        }],
    };

    for base in bases(repo)? {
        // Absent at the base: there is no history to preserve, so every row is
        // an append. This is the first-commit case, not a skipped check.
        if let Some(text) = at_rev(repo, &base, &declared.path)?
            && let Some(line) = first_divergence(&text, &working)
        {
            problems.push(Problem {
                line,
                id: NOT_APPEND_ONLY,
            });
        }
    }

    // Two bases that resolve to the same commit find the same divergence twice;
    // one rewrite is one finding.
    problems.sort_by_key(|problem| (problem.line, problem.id));
    problems.dedup();
    Ok(problems
        .iter()
        .map(|problem| problem.finding(&declared.path))
        .collect())
}

/// Validate a parsed ledger against the declared taxonomy and id uniqueness.
///
/// Returns every problem rather than the first, so one run names everything to
/// fix. Sorted by line, so the report is byte-stable.
#[must_use]
pub fn validate_records(records: &[Record], classes: &[String]) -> Vec<Problem> {
    let allowed: BTreeSet<&str> = classes.iter().map(String::as_str).collect();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut problems = Vec::new();
    for (index, record) in records.iter().enumerate() {
        let line = index + 1;
        if !allowed.contains(record.class.as_str()) {
            problems.push(Problem {
                line,
                id: UNKNOWN_CLASS,
            });
        }
        if !seen.insert(record.id.as_str()) {
            problems.push(Problem {
                line,
                id: DUPLICATE_ID,
            });
        }
    }
    problems.sort_by_key(|problem| (problem.line, problem.id));
    problems
}

/// Whether `base` is a byte prefix of `working`, and where it first diverges.
///
/// `None` means append-only held. `Some(line)` is the 1-based line of the first
/// divergence — the row that was rewritten, or the first row missing when the
/// ledger shrank.
///
/// Compared line by line rather than as a raw byte prefix so the finding can
/// carry a line number. The predicate is the same: every base line must survive
/// unchanged, in order.
#[must_use]
pub fn first_divergence(base: &str, working: &str) -> Option<usize> {
    let base_lines: Vec<&str> = base.lines().collect();
    let working_lines: Vec<&str> = working.lines().collect();
    for (index, base_line) in base_lines.iter().enumerate() {
        match working_lines.get(index) {
            // A rewritten row.
            Some(working_line) if working_line != base_line => return Some(index + 1),
            // The ledger shrank: the row is simply gone.
            None => return Some(index + 1),
            Some(_) => {}
        }
    }
    None
}

/// Read the ledger as it stands at `rev`, or `None` when it is not there.
///
/// A ledger absent at the base is the ordinary first-commit case, not a failure:
/// there is no history to preserve yet, so every row is an append.
///
/// Read through [`crate::git::show`], which resolves the blob in-process rather
/// than spelling `{rev}:{path}` into argv — the shape CLOUD-718 closed on the
/// trust boundary, and `rev` here comes from [`bases`] and `path` from config.
/// Its refusals stay refusals-as-absence at this call site, because that is what
/// the append-only comparison already means by "not there".
///
/// # Errors
///
/// Infallible today; the signature matches its caller's so both read the same.
pub fn at_rev(repo: &Path, rev: &str, path: &str) -> Result<Option<String>> {
    Ok(crate::git::show(repo, rev, path).ok())
}

/// Which ids `filter` selects, given the whole ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Filter<'a> {
    /// Every record.
    All,
    /// Records in one taxonomy class.
    Class(&'a str),
    /// One record by id.
    Id(&'a str),
    /// Records with no `enforcement` — the lessons still ungated.
    Ungated,
}

impl Filter<'_> {
    /// Whether `record` passes.
    #[must_use]
    pub fn admits(self, record: &Record) -> bool {
        match self {
            Filter::All => true,
            Filter::Class(class) => record.class == class,
            Filter::Id(id) => record.id == id,
            Filter::Ungated => record.enforcement.is_none(),
        }
    }
}

/// One query result line: `<path>:<line> <id>[ <enforcement>]`.
///
/// Pointer-only: an id, a location, and the gate id that discharges it. The
/// record's `evidence` and `observed` are deliberately absent from the default
/// channel — a query is for finding rows, and `-J` is for reading them.
#[must_use]
pub fn query_lines(records: &[Record], path: &str, filter: Filter<'_>) -> Vec<String> {
    let mut matched: Vec<(usize, &Record)> = records
        .iter()
        .enumerate()
        .filter(|(_, record)| filter.admits(record))
        .collect();
    matched.sort_by(|(_, a), (_, b)| a.id.cmp(&b.id));
    matched
        .into_iter()
        .map(|(index, record)| match &record.enforcement {
            Some(enforcement) => {
                format!("{path}:{} {} {enforcement}", index + 1, record.id)
            }
            None => format!("{path}:{} {} ungated", index + 1, record.id),
        })
        .collect()
}

/// What an `add` would do, or did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Added {
    /// Rows that are new and would be appended.
    pub appended: usize,
    /// Rows already present byte-identically, so appending them is a no-op.
    ///
    /// Idempotence is what makes the importer re-runnable: a migration that
    /// half-completed can simply be run again.
    pub already: usize,
}

/// Decide what appending `incoming` to `existing` would do.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when an incoming row reuses an existing
/// id with different content. That is the one case that is neither an append nor
/// a no-op: it is an attempt to revise, and a revision is a new row carrying
/// `supersedes`.
pub fn plan(existing: &[Record], incoming: &[Record]) -> Result<(Added, Vec<Record>)> {
    let mut summary = Added::default();
    let mut fresh = Vec::new();
    // Rows already staged in this batch count as present, so a stream carrying
    // the same row twice appends it once.
    let mut known: Vec<Record> = existing.to_vec();

    for record in incoming {
        match known.iter().find(|held| held.id == record.id) {
            Some(held) if held == record => summary.already += 1,
            Some(_) => {
                return Err(UsageError::raise(format!(
                    "defects: id `{}` already exists with different content; a correction is a \
                     new row carrying `supersedes`, never an edit",
                    record.id
                )));
            }
            None => {
                summary.appended += 1;
                known.push(record.clone());
                fresh.push(record.clone());
            }
        }
    }
    Ok((summary, fresh))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn record(id: &str, class: &str) -> Record {
        Record {
            id: id.to_owned(),
            class: class.to_owned(),
            observed: "2026-08-11".to_owned(),
            evidence: "crates/batten/src/lib.rs:1".to_owned(),
            enforcement: None,
            supersedes: None,
        }
    }

    fn classes() -> Vec<String> {
        vec!["false-green".to_owned(), "silent-skip".to_owned()]
    }

    #[test]
    fn append_only_freezes_the_bytes_of_every_past_row() {
        let base = "{\"a\":1}\n{\"b\":2}\n";

        // Appending is the permitted move.
        assert_eq!(
            first_divergence(base, "{\"a\":1}\n{\"b\":2}\n{\"c\":3}\n"),
            None
        );
        assert_eq!(first_divergence(base, base), None);

        // Rewriting a row is caught at that row, not at the end.
        assert_eq!(
            first_divergence(base, "{\"a\":1}\n{\"b\":99}\n"),
            Some(2),
            "the finding points at the row that changed"
        );
        assert_eq!(first_divergence(base, "{\"a\":0}\n{\"b\":2}\n"), Some(1));

        // Shrinking is caught at the first row that went missing.
        assert_eq!(first_divergence(base, "{\"a\":1}\n"), Some(2));
        assert_eq!(first_divergence(base, ""), Some(1));
    }

    #[test]
    fn a_prefix_is_stronger_than_a_growing_id_set() {
        // The reason the predicate is bytes rather than ids: this edit keeps
        // every id and still rewrites history.
        let base = "{\"id\":\"d-1\",\"evidence\":\"a\"}\n";
        let revised = "{\"id\":\"d-1\",\"evidence\":\"b\"}\n";
        assert_eq!(first_divergence(base, revised), Some(1));
    }

    #[test]
    fn an_absent_base_ledger_is_the_first_commit_not_a_failure() {
        assert_eq!(first_divergence("", "{\"a\":1}\n"), None);
    }

    #[test]
    fn a_class_outside_the_taxonomy_is_a_problem_naming_its_line() {
        let records = vec![
            record("d-1", "false-green"),
            record("d-2", "invented-locally"),
        ];
        let problems = validate_records(&records, &classes());
        assert_eq!(
            problems,
            vec![Problem {
                line: 2,
                id: UNKNOWN_CLASS
            }]
        );
    }

    #[test]
    fn a_repeated_id_is_a_problem_at_the_second_row() {
        let records = vec![record("d-1", "false-green"), record("d-1", "silent-skip")];
        let problems = validate_records(&records, &classes());
        assert_eq!(
            problems,
            vec![Problem {
                line: 2,
                id: DUPLICATE_ID
            }]
        );
    }

    #[test]
    fn every_problem_is_reported_not_only_the_first() {
        // One run names everything to fix; a first-error-only gate makes the
        // author re-run it once per mistake.
        let records = vec![
            record("d-1", "false-green"),
            record("d-1", "invented-locally"),
        ];
        let problems = validate_records(&records, &classes());
        assert_eq!(problems.len(), 2, "both the class and the id are named");
    }

    #[test]
    fn adding_is_idempotent_and_a_revision_is_refused() {
        let existing = vec![record("d-1", "false-green")];

        // Byte-identical: a no-op, which is what makes a half-finished import
        // safe to re-run.
        let (summary, fresh) = plan(&existing, &existing).unwrap();
        assert_eq!(
            summary,
            Added {
                appended: 0,
                already: 1
            }
        );
        assert!(fresh.is_empty());

        // New id: an append.
        let (summary, fresh) = plan(&existing, &[record("d-2", "silent-skip")]).unwrap();
        assert_eq!(
            summary,
            Added {
                appended: 1,
                already: 0
            }
        );
        assert_eq!(fresh.len(), 1);

        // Same id, different content: neither an append nor a no-op.
        let mut revised = record("d-1", "false-green");
        revised.evidence = "somewhere/else.rs:9".to_owned();
        let err = plan(&existing, &[revised]).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
        assert!(
            format!("{err}").contains("supersedes"),
            "the refusal names the sanctioned way to correct a row"
        );
    }

    #[test]
    fn a_stream_carrying_one_row_twice_appends_it_once() {
        let twice = vec![record("d-1", "false-green"), record("d-1", "false-green")];
        let (summary, fresh) = plan(&[], &twice).unwrap();
        assert_eq!(
            summary,
            Added {
                appended: 1,
                already: 1
            }
        );
        assert_eq!(fresh.len(), 1);
    }

    #[test]
    fn a_query_is_pointer_only_and_sorted_by_id() {
        let mut gated = record("d-2", "false-green");
        gated.enforcement = Some("no-todo".to_owned());
        let records = vec![
            record("d-3", "silent-skip"),
            gated,
            record("d-1", "false-green"),
        ];

        let all = query_lines(&records, "defects.jsonl", Filter::All);
        assert_eq!(
            all,
            vec![
                "defects.jsonl:3 d-1 ungated".to_owned(),
                "defects.jsonl:2 d-2 no-todo".to_owned(),
                "defects.jsonl:1 d-3 ungated".to_owned(),
            ],
            "sorted by id, located by line"
        );
        assert!(
            !all.join("\n").contains("2026-08-11"),
            "the default channel carries no record body"
        );

        // The filter that matters: which lessons are still prose.
        let ungated = query_lines(&records, "defects.jsonl", Filter::Ungated);
        assert_eq!(ungated.len(), 2);
        assert_eq!(
            query_lines(&records, "defects.jsonl", Filter::Class("silent-skip")).len(),
            1
        );
        assert_eq!(
            query_lines(&records, "defects.jsonl", Filter::Id("d-2")).len(),
            1
        );
    }

    #[test]
    fn a_blank_line_is_not_a_record_and_a_bad_one_names_its_line() {
        let text = "{\"id\":\"d-1\",\"class\":\"false-green\",\"observed\":\"2026-08-11\",\"evidence\":\"a:1\"}\n\n";
        assert_eq!(
            parse(text).unwrap().len(),
            1,
            "a trailing newline is not a row"
        );

        let bad = format!("{text}not json\n");
        let err = parse(&bad).unwrap_err();
        assert!(format!("{err}").contains("line 3"), "got: {err}");
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_dropped() {
        // `deny_unknown_fields`: a row carrying a key the schema does not know
        // would otherwise be stored with that key silently discarded, which in a
        // permanent ledger is data loss nobody sees.
        let text =
            "{\"id\":\"d-1\",\"class\":\"c\",\"observed\":\"d\",\"evidence\":\"e\",\"bogus\":1}\n";
        assert!(parse(text).is_err());
    }

    #[test]
    fn a_table_that_cannot_be_used_is_refused() {
        let ok = Defects {
            path: "defects.jsonl".to_owned(),
            classes: classes(),
        };
        assert!(ok.validate().is_ok());
        assert!(
            Defects {
                classes: Vec::new(),
                ..ok.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Defects {
                path: "  ".to_owned(),
                ..ok.clone()
            }
            .validate()
            .is_err()
        );
        assert!(
            Defects {
                classes: vec!["a".to_owned(), "a".to_owned()],
                ..ok
            }
            .validate()
            .is_err()
        );
    }
}
