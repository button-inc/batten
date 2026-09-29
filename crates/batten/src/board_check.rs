//! `batten board check`: whether the board's columns, its dependency graph and
//! its citations tell the truth about the work (CLOUD-175, CLOUD-826, CLOUD-809),
//! retired whole off `mise-tasks/graph-check.sh`, `mise-tasks/ready-cites-check.sh`
//! and `mise-tasks/spec-ref-check.sh` under CLOUD-1221.
//!
//! # Three questions over one payload set
//!
//! The board is the observability surface the whole workflow contract leans on,
//! and its discipline was prose until these gates made it computable. They were
//! three shell programs reading the same `get_issue` payloads, each re-deriving
//! the Ready grammar it needed, and one of them spawning a fourth
//! (`ready-lint`) per row. They are one verb here, over one reading of the set:
//!
//! - **the graph** (the default): a column is a CLAIM, so an unassigned row In
//!   Progress, a row In Review with nothing landed, an unready row in the ready
//!   queue or an unphased started row is the board signalling falsely; the
//!   `blockedBy` relation is acyclic; a prose gloss of another row's column
//!   agrees with the board. The READY FRONTIER — ready-queue rows whose block
//!   passes the refinement gate and whose blockers are settled — is the
//!   by-product on stdout, which is what makes the same command the scheduler.
//! - **`--cites`**: a Ready block's citations name things the TREE carries — a
//!   test obligation names a test that exists, a cited path exists or is marked
//!   prospective (CLOUD-920), and a citation resolving only in an excluded path
//!   (a fixture quoting the citation) is refused.
//! - **`--refs`**: every clause citation IN the tree names a clause its issue
//!   actually carries (CLOUD-809) — the other direction of the same join.
//!
//! # The refinement gate is ASKED, never re-derived
//!
//! A ready-queue row is judged by [`crate::ready::lint`] over its own payload —
//! the one definition of Ready — and that verdict's rule ids are forwarded as it
//! wrote them. The In Review exemption for a row declaring that it lands no
//! commit (CLOUD-735) reads the `bump` fact the same lint emits, never a second
//! parse of the clause.
//!
//! # Repo-agnostic by construction (non-negotiable rule 1)
//!
//! Every consumer fact arrives from `batten.toml`: which columns are the ready
//! queue, pulled and landed (`[board]`), which status types settle a blocker,
//! which receipt a coherent board mints, which paths a citation resolves
//! against, and every expression — the issue key, the status connective, the
//! clause citation — from the `[[pattern]]` registry. A linked pull request is
//! `landed`'s one reading of a pull-request URL rather than a host literal. An
//! undeclared one is could-not-look, NAMED, never a default: a
//! default would put one tracker's vocabulary back in the engine and make the
//! dead path byte-identical to the working one, which is the failure
//! `crate::board` exists to refuse.
//!
//! # Three channels, and they never collapse
//!
//! A line on stderr is `<id> <rule>` — a report (the board is lying, exit `2`),
//! an unjudged gap (the caller did not pipe enough to judge, exit `3`), or a note
//! (an honest frontier exclusion, exit unmoved). A gap outranks a report in the
//! graph, because a verdict over a set only partly read is not a verdict: the
//! caller's next action is a re-fetch, after which more violations may appear.
//! Both report sets print before the exit either way, so one never hides the
//! other.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! An id, a rule, a column word, a path and line, a count — never a byte of an
//! issue body and never a line of a source file. Bodies carry customer detail.
//!
//! # The decisions here are OWED to a preset, and this is not their home
//!
//! The migration's rule puts a generic decision in a preset bundle and only the
//! mechanism in the engine; this package's row named the `tracker-hygiene`
//! bundle. An earlier revision of this header argued that no Rego module could
//! read a payload set, and that is refuted in this tree: `duplicate-close-check`
//! records piped payloads as facts and decides over them in
//! `policy/duplicate-close.rego`. So the predicates below — the column claims,
//! the `blockedBy` graph, the frontier, the citation joins — are a port still
//! owed, recorded as a blocker on CLOUD-1221 rather than defended as a design.
//! Every vocabulary they decide with is already the consumer's, which is the
//! half of the move that is done.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;

use regex::Regex;
use serde_json::Value;

use crate::Result;
use crate::board::Board;
use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::pattern::NamedPattern;
use crate::ready::Grammar;

// The `[[pattern]]` row ids this module reads beyond the Ready grammar, each
// spelled once and read at its one call site: the graph's status connective,
// then `--cites`'s three rows, then `--refs`'s two.

/// The graph's status connective.
const STATUS_CONNECTIVE: &str = "board-status-connective";
/// `--cites`: the obligations label of a Ready block.
const OBLIGATIONS_LABEL: &str = "ready-obligations-label";
/// `--cites`: a cited test name.
const CITED_TEST: &str = "ready-cited-test";
/// `--cites`: a cited path.
const CITED_PATH: &str = "ready-cited-path";
/// `--refs`: the clause tail after an issue key.
const CLAUSE_CITATION: &str = "board-clause-citation";
/// `--refs`: a clause tag a Ready block declares.
const CLAUSE_TAG: &str = "ready-clause-tag";

/// The pseudo-id a property of the whole piped SET is reported under.
///
/// Set-keyed deliberately: a reader asking about one row greps `^<id> <rule>`,
/// and a per-row line for a property of the closure would turn every row of a
/// thin fetch into a refusal of that row.
const SET: &str = "graph";

/// A code span or a quoted phrase NAMES a claim rather than making one, so both
/// are neutralised before the status scan — the reason this gate does not fail
/// the very row that ships it, whose body quotes the defect it fixes.
const CODE_SPAN: &str = "`[^`]*`";

/// See [`CODE_SPAN`].
const QUOTED: &str = r#""[^"]*""#;

/// A capitalised span of one or more words: what stands in for a column the
/// piped set's alphabet cannot spell (CLOUD-838). Multi-word because the columns
/// it has to name are, and reporting `In` for a claim of a two-word column would
/// point at nothing a reader can act on.
const CAPITALISED: &str = "[A-Z][A-Za-z]*(?:[[:space:]]+[A-Z][A-Za-z]*)*";

/// What `board check` was asked, beyond the configuration.
#[derive(Debug, Clone, Copy)]
pub struct Ask<'a> {
    /// The payload set: one JSON array, or a stream of objects.
    pub text: &'a str,
    /// Judge the payloads' citations against the tree.
    pub cites: bool,
    /// Judge the tree's clause citations against the payloads.
    pub refs: bool,
    /// The boundary's clock, stamped into a minted receipt for a human reader.
    pub now: u64,
}

/// What the consumer declared, resolved once at the boundary.
#[derive(Debug, Clone, Copy)]
pub struct Declared<'a> {
    /// The `[board]` table, if any.
    pub board: Option<&'a Board>,
    /// The `[[pattern]]` rows.
    pub patterns: &'a [NamedPattern],
    /// The Ready grammar, already built from those rows.
    pub grammar: &'a Grammar,
    /// The checkout whose tree is read — the workspace version for the Ready
    /// gate's §6 arrows, the tracked paths for the citations.
    pub root: &'a Path,
}

/// Run the verb: the graph by default, the citation directions on request.
///
/// # Errors
///
/// [`UsageError`] when the consumer has not declared a column, a status type or
/// a pattern row the asked question needs — could-not-look, named by key.
/// Otherwise only when a write to `out` or `err` fails.
pub fn run(
    ask: &Ask<'_>,
    declared: &Declared<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let Some(set) = payload_set(ask.text) else {
        writeln!(
            err,
            "::error:: board check: stdin is not JSON — expected get_issue payloads, one array or a stream"
        )?;
        return Ok(ExitCode::Internal);
    };
    if !ask.cites && !ask.refs {
        return graph(&set, declared, ask.now, out, err);
    }
    let mut refused = false;
    let mut unjudged = false;
    if ask.cites {
        let cites = Cites::resolve(declared)?;
        match cites.judge(&set, declared) {
            Ok(tally) => refused |= tally.render(out, err)?,
            Err(why) => {
                writeln!(err, "::error:: board check --cites: {why}")?;
                unjudged = true;
            }
        }
    }
    if ask.refs {
        let refs = Refs::resolve(declared)?;
        match refs.judge(&set, declared) {
            Ok(found) => {
                let (proven, gaps) = found.render(out, err)?;
                refused |= proven;
                unjudged |= gaps;
            }
            Err(why) => {
                writeln!(err, "::error:: board check --refs: {why}")?;
                unjudged = true;
            }
        }
    }
    // A PROVEN FINDING OUTRANKS A GAP IN THE CITATION DIRECTIONS, deliberately
    // and against the graph's order: a citation proved wrong is wrong whatever
    // else could not be seen, and could-not-look would let it hide behind an
    // unfetched sibling.
    Ok(if refused {
        ExitCode::Violation
    } else if unjudged {
        ExitCode::Internal
    } else {
        ExitCode::Success
    })
}

/// The payload set on stdin: one JSON array, or a stream of values — `jq -s`'s
/// normalisation, carried. `None` is unreadable input.
#[must_use]
pub fn payload_set(text: &str) -> Option<Vec<Value>> {
    let mut values = Vec::new();
    for value in serde_json::Deserializer::from_str(text).into_iter::<Value>() {
        values.push(value.ok()?);
    }
    if let [Value::Array(items)] = values.as_slice() {
        return Some(items.clone());
    }
    Some(values)
}

/// `jq`'s `//`: null and `false` are absent, everything else is present.
fn present(value: &Value) -> bool {
    !matches!(value, Value::Null | Value::Bool(false))
}

/// A scalar as `jq -r` prints it.
fn scalar(value: &Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_owned)
}

/// The byte-stable order every report uses: by the number after the key's
/// separator, then by the whole id — `sort -t- -k2,2n`, so a later row never
/// sorts ahead of an earlier one for being lexically smaller.
fn by_num(id: &str) -> (u64, &str) {
    let tail = id.split_once('-').map_or("", |(_, rest)| rest);
    let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
    (digits.parse().unwrap_or(0), id)
}

/// Sort ids into [`by_num`] order, in place.
fn sort_ids(ids: &mut [String]) {
    ids.sort_by(|left, right| by_num(left).cmp(&by_num(right)));
}

/// One `[[pattern]]` row, compiled, or could-not-look naming it.
fn declared_row(patterns: &[NamedPattern], id: &str) -> Result<Regex> {
    let row = patterns.iter().find(|row| row.id == id).ok_or_else(|| {
        UsageError::raise(format!(
            "board check: this repository declares no `[[pattern]]` row `{id}`, so the \
             question it anchors could not be judged at all — which is not the same as clean"
        ))
    })?;
    Regex::new(&row.regex).map_err(|_| {
        UsageError::raise(format!(
            "board check: the `[[pattern]]` row `{id}` does not compile as a regular expression"
        ))
    })
}

/// An expression this module composes, or could-not-look.
fn composed(expression: &str) -> Result<Regex> {
    Regex::new(expression).map_err(|_| {
        UsageError::raise(
            "board check: an expression composed from the declared rows does not compile"
                .to_owned(),
        )
    })
}

/// A key the consumer did not declare.
fn undeclared(key: &str) -> anyhow::Error {
    UsageError::raise(format!(
        "board check: `{key}` is not declared, so this decides nothing rather than guessing \
         the board's vocabulary"
    ))
}

/// A list of globs, compiled.
fn selectors(globs: &[String]) -> Result<Vec<crate::rules::Selector>> {
    globs
        .iter()
        .map(|glob| crate::rules::Selector::new(glob.as_str()))
        .collect()
}

/// Every tracked path one of `keep` selects and none of `drop` does.
fn corpus_paths(
    root: &Path,
    keep: &[crate::rules::Selector],
    drop: &[crate::rules::Selector],
) -> std::result::Result<Vec<String>, String> {
    let tracked = crate::git::tracked_paths(root).map_err(|_| {
        "no repository root to scan — this reads the tree and must not guess".to_owned()
    })?;
    Ok(tracked
        .into_iter()
        .filter(|path| keep.iter().any(|glob| glob.matches(path)))
        .filter(|path| !drop.iter().any(|glob| glob.matches(path)))
        .collect())
}

// --- the graph ----------------------------------------------------------------

/// The board's words, each proven declared.
#[derive(Debug)]
pub struct Vocabulary {
    ready: String,
    in_progress: String,
    review: String,
    settled_types: Vec<String>,
    retired_types: Vec<String>,
    connective: String,
}

impl Vocabulary {
    /// Resolve every word the graph decides with.
    ///
    /// # Errors
    ///
    /// [`UsageError`] naming the first undeclared column, type set or row.
    pub fn resolve(board: Option<&Board>, patterns: &[NamedPattern]) -> Result<Self> {
        let board = board.ok_or_else(|| undeclared("board"))?;
        let column = |value: Option<&str>, key: &str| -> Result<String> {
            value.map(str::to_owned).ok_or_else(|| undeclared(key))
        };
        if board.settled_types.is_empty() {
            return Err(undeclared("board.settled_types"));
        }
        // Compiled here and kept as its source: the claim scan composes it into a
        // wider expression, and a row that will not compile on its own must be
        // refused by name rather than silently disabling that scan.
        let connective = declared_row(patterns, STATUS_CONNECTIVE)?
            .as_str()
            .to_owned();
        Ok(Self {
            ready: column(board.ready.as_deref(), "board.ready")?,
            in_progress: column(board.in_progress.as_deref(), "board.in_progress")?,
            review: column(board.review.as_deref(), "board.review")?,
            settled_types: board.settled_types.clone(),
            retired_types: board.retired_types.clone(),
            connective,
        })
    }

    /// A column that claims the row is at least pullable — the ready queue, the
    /// pulled column and the landed one (CLOUD-771).
    fn started(&self, status: &str) -> bool {
        status == self.ready || status == self.in_progress || status == self.review
    }
}

/// Whether a payload carries a milestone: the key absent, present-but-empty, or
/// set. Absent and empty are different answers — the tracker OMITS the key when
/// it is null, so only the SET can tell "none" from "projected away".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Absent,
    Empty,
    Set,
}

/// One payload, read once.
#[derive(Debug)]
struct Row<'a> {
    id: String,
    status: String,
    status_type: Option<String>,
    assigned: bool,
    prs: usize,
    milestone: Presence,
    parent: Option<String>,
    edges_declared: bool,
    blocked_by: Vec<String>,
    description: Option<&'a str>,
    value: &'a Value,
}

impl<'a> Row<'a> {
    /// `None` for a payload carrying no `id` or no `status` — the input refusal.
    ///
    /// A linked pull request is `landed`'s one reading of a pull-request URL
    /// (CLOUD-1623), never a host literal of this module's own.
    fn read(value: &'a Value) -> Option<Self> {
        let object = value.as_object()?;
        let id = scalar(object.get("id")?);
        let status = scalar(object.get("status")?);
        let prs = object
            .get("attachments")
            .and_then(Value::as_array)
            .map_or(0, |items| {
                items
                    .iter()
                    .filter_map(|item| item.get("url").and_then(Value::as_str))
                    .filter(|url| crate::landed::is_pull_request_url(url))
                    .count()
            });
        let milestone = match object.get("projectMilestone") {
            None => Presence::Absent,
            Some(value) if present(value) => Presence::Set,
            Some(_) => Presence::Empty,
        };
        let relations = object.get("relations");
        let edges_declared = relations
            .and_then(Value::as_object)
            .is_some_and(|relations| relations.contains_key("blockedBy"));
        let blocked_by = relations
            .and_then(|relations| relations.get("blockedBy"))
            .and_then(Value::as_array)
            .map(|edges| {
                edges
                    .iter()
                    .filter_map(|edge| edge.get("id").and_then(Value::as_str))
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default();
        Some(Self {
            id,
            status,
            status_type: object
                .get("statusType")
                .filter(|value| present(value))
                .map(scalar),
            assigned: object.get("assigneeId").is_some_and(present),
            prs,
            milestone,
            parent: object
                .get("parentId")
                .filter(|value| present(value))
                .map(scalar),
            edges_declared,
            blocked_by,
            description: object.get("description").and_then(Value::as_str),
            value,
        })
    }

    fn milestoned(&self) -> bool {
        self.milestone == Presence::Set
    }

    /// Whether the payload carried the milestone key at all, empty or not.
    fn carries_milestone_key(&self) -> bool {
        self.milestone != Presence::Absent
    }
}

/// What the graph decided, in the order it was decided.
#[derive(Debug, Default)]
pub struct Judgement {
    /// The stderr pointer lines, in emission order: `<id> <rule>`.
    pub lines: Vec<String>,
    /// How many say the board is signalling falsely.
    pub violations: usize,
    /// How many say the set could not answer.
    pub unjudgeable: usize,
    /// How many rows sit in the pulled column.
    pub wip: usize,
    /// The ready frontier, in byte-stable order.
    pub frontier: Vec<String>,
    /// Every row judged, in byte-stable order.
    pub ids: Vec<String>,
}

impl Judgement {
    /// The board is signalling falsely.
    fn report(&mut self, id: &str, rule: &str) {
        self.lines.push(format!("{id} {rule}"));
        self.violations += 1;
    }

    /// An honest frontier exclusion: attributed, and the exit code unmoved.
    fn note(&mut self, id: &str, rule: &str) {
        self.lines.push(format!("{id} {rule}"));
    }

    /// The caller did not pipe enough to judge.
    fn unjudged(&mut self, id: &str, rule: &str) {
        self.note(id, rule);
        self.unjudgeable += 1;
    }
}

/// What the refinement gate said about one row, and the §6 fact it emitted.
#[derive(Debug)]
enum Readiness {
    Ready,
    /// Its own pointer lines, forwarded rather than re-derived.
    Unready(Vec<String>),
    /// The gate could not read it, or could not cross-check it.
    Unjudgeable,
}

/// Ask the one definition of Ready about one payload.
///
/// The `bump` token rides along because the In Review exemption reads it: the
/// gate emits it whatever its verdict, so a refused row still says what its §6
/// declared. A payload the gate could not read at all declares nothing, which
/// leaves `in-review-no-pr` deciding exactly as it would without the clause —
/// could-not-look must not manufacture an exemption.
fn readiness(grammar: &Grammar, value: &Value, root: &Path) -> (Readiness, Option<String>) {
    let Ok(payload) = crate::ready::Payload::parse(value) else {
        return (Readiness::Unjudgeable, None);
    };
    let Ok(report) = crate::ready::lint(grammar, &payload, root) else {
        return (Readiness::Unjudgeable, None);
    };
    let bump = report
        .emissions
        .iter()
        .find_map(|line| line.strip_prefix("bump "))
        .map(str::to_owned);
    if !report.findings.is_empty() {
        let mut lines: Vec<String> = report
            .findings
            .iter()
            .map(|finding| format!("{}:{} {}", payload.id, finding.line, finding.rule))
            .collect();
        if report.unjudgeable > 0 {
            lines.push(format!(
                "{}:{} unjudgeable-relations",
                payload.id, report.unjudged_line
            ));
        }
        return (Readiness::Unready(lines), bump);
    }
    if report.unjudgeable > 0 {
        return (Readiness::Unjudgeable, bump);
    }
    (Readiness::Ready, bump)
}

/// The piped set, indexed once (CLOUD-634).
#[derive(Debug)]
struct Closure<'a> {
    rows: Vec<Row<'a>>,
    index: BTreeMap<String, usize>,
    grammar: &'a Grammar,
    vocabulary: &'a Vocabulary,
    root: &'a Path,
}

impl Closure<'_> {
    /// The FIRST row carrying `id`, or `None` when the set does not carry it —
    /// and that `None` is load-bearing: "I was not given this row" is never
    /// "this row has not completed" (CLOUD-678).
    fn row(&self, id: &str) -> Option<&Row<'_>> {
        self.index.get(id).and_then(|at| self.rows.get(*at))
    }

    /// Does a blocker no longer hold its dependent back? (CLOUD-477.)
    ///
    /// A settled TYPE — completed, or retired for good — or the review column by
    /// NAME, since landed code is on the trunk and a dependent can build on it.
    fn settled(&self, blocker: &Row<'_>) -> bool {
        let typed = blocker
            .status_type
            .as_deref()
            .is_some_and(|kind| self.vocabulary.settled_types.iter().any(|t| t == kind));
        if typed {
            return true;
        }
        blocker.status == self.vocabulary.review
    }

    /// Whether a settled blocker settled by being RETIRED rather than completed.
    fn retired(&self, blocker: &Row<'_>) -> bool {
        blocker
            .status_type
            .as_deref()
            .is_some_and(|kind| self.vocabulary.retired_types.iter().any(|t| t == kind))
    }
}

// THE DECLARED MUTATIONS, beside the predicates they unmake. One suite serves
// every row in this file, because `batten mutate` reads the FIRST
// `MUTANT-SUITE` line of a source — so the graph, citation and clause-reference
// tiers live in one compiled suite, as three inner modules. No pattern or case
// here carries a `|`: the row is split on it, and a closure's pipes would shift
// every field after them. That is why the lines they target are written without
// closures.
//MUTANT-SUITE crates/batten/tests/it/board_check.rs
//MUTANT in-progress-unassigned-passes|s@^    if row.status == vocabulary.in_progress && !row.assigned {$@    if false {@|an_unassigned_in_progress_issue_is_reported
//MUTANT in-review-none-not-exempt|s@^        if row.prs == 0 && !declares_none {$@        if row.prs == 0 {@|an_in_review_row_declaring_no_commit_is_exempt_from_in_review_no_pr
//MUTANT declared-none-with-pr-passes|s@^        if row.prs != 0 && declares_none {$@        if false {@|a_row_declaring_no_commit_that_carries_a_pr_is_refused_for_the_contradiction
//MUTANT milestone-refusal-is-a-note|s@^                judgement.report(&row.id, &format!("unmilestoned ({})", row.status));$@                judgement.note(\&row.id, \&format!("unmilestoned ({})", row.status));@|a_todo_issue_with_no_milestone_in_a_set_where_others_carry_one_is_refused
//MUTANT child-refusal-is-a-note|s@^                judgement.report(&row.id, &format!("child-unmilestoned (parent {parent})"));$@                judgement.note(\&row.id, \&format!("child-unmilestoned (parent {parent})"));@|a_child_with_no_milestone_under_a_milestoned_parent_is_refused
//MUTANT declared-rephase-refused|s@^            Some(found) if found.milestoned() && !row.milestoned() => {$@            Some(found) if found.milestoned() => {@|a_child_carrying_a_different_milestone_is_the_declared_rephase_and_passes
//MUTANT absent-milestone-key-judged|s@^    if closure.rows.iter().any(Row::carries_milestone_key) {$@    if true {@|a_set_with_the_field_absent_everywhere_is_unjudgeable_not_a_wall_of_violations
//MUTANT absent-blocker-reads-as-resolved|s@^            let Some(blocker) = closure.row(to) else {$@            let Some(blocker) = closure.row(to).or(Some(row)) else {@|a_blocker_outside_the_piped_set_is_unjudgeable_not_resolved
//MUTANT settled-type-ignored|s@^        if typed {$@        if false {@|a_todo_row_whose_only_blocker_is_canceled_reaches_the_frontier
//MUTANT in-review-loses-its-name-arm|s@^        blocker.status == self.vocabulary.review$@        false@|a_blocker_in_review_still_resolves_since_its_type_is_started
//MUTANT retirement-is-silent|s@^            if !retired.is_empty() {$@            if false {@|a_frontier_row_over_a_retired_blocker_says_so
//MUTANT todo-refusal-is-a-note|s@^                judgement.report(&row.id, "todo-not-ready");$@                judgement.note(\&row.id, "todo-not-ready");@|a_todo_issue_with_no_ready_block_is_refused
//MUTANT cycle-unseen|s@^        if node == start {$@        if false {@|a_blocked_by_cycle_is_reported_with_its_members
//MUTANT unscannable-refusal-is-a-note|s@^                judgement.unjudged(SET, &unscannable);$@                judgement.note(SET, \&unscannable);@|a_claim_naming_a_column_no_piped_issue_occupies_is_refused_not_ignored
//MUTANT claim-disagreement-passes|s@^                    Some(actual) if actual.status != claimed => {$@                    Some(actual) if false \&\& actual.status != claimed => {@|a_body_claiming_a_column_the_board_contradicts_is_reported

/// Judge the graph over a payload set.
///
/// `None` is an input refusal: an empty set, or a payload carrying no `id` or no
/// `status`.
#[must_use]
pub fn judge(
    set: &[Value],
    grammar: &Grammar,
    vocabulary: &Vocabulary,
    root: &Path,
) -> Option<Judgement> {
    if set.is_empty() {
        return None;
    }
    let mut rows = Vec::with_capacity(set.len());
    for value in set {
        rows.push(Row::read(value)?);
    }
    rows.sort_by(|left, right| by_num(&left.id).cmp(&by_num(&right.id)));
    let mut index = BTreeMap::new();
    for (at, row) in rows.iter().enumerate() {
        index.entry(row.id.clone()).or_insert(at);
    }
    let closure = Closure {
        rows,
        index,
        grammar,
        vocabulary,
        root,
    };
    let mut judgement = Judgement::default();
    let milestones_judgeable = milestone_presence(&closure, &mut judgement);
    for row in &closure.rows {
        judge_row(&closure, row, milestones_judgeable, &mut judgement);
    }
    let edges = judge_edges(&closure, &mut judgement);
    judge_claims(&closure, &mut judgement);
    judge_frontier(&closure, &edges, &mut judgement);
    judgement.wip = closure
        .rows
        .iter()
        .filter(|row| row.status == vocabulary.in_progress)
        .count();
    judgement.ids = closure.rows.iter().map(|row| row.id.clone()).collect();
    Some(judgement)
}

/// The milestone claim's anti-vacuity arm (CLOUD-695, widened by CLOUD-771).
///
/// The tracker OMITS a null milestone, so per row "no milestone" and "the caller
/// projected the field away" are the same bytes. The discriminator is the SET:
/// if no row anywhere carries the key, the caller projected it away. The honest
/// limit — a set in which every row is genuinely unphased reads as projected
/// away — is the could-not-look direction, and the remedy is one re-fetch.
fn milestone_presence(closure: &Closure<'_>, judgement: &mut Judgement) -> bool {
    let started: Vec<&str> = closure
        .rows
        .iter()
        .filter(|row| closure.vocabulary.started(&row.status))
        .map(|row| row.id.as_str())
        .collect();
    if started.is_empty() {
        return true;
    }
    if closure.rows.iter().any(Row::carries_milestone_key) {
        return true;
    }
    judgement.unjudged(
        SET,
        &format!("unjudgeable-milestone ({})", started.join(" ")),
    );
    false
}

/// The per-row column claims.
///
/// - `in-progress-unassigned`: pulled means somebody has it.
/// - `in-review-no-pr`: landed means a pull request is attached — a deliberate
///   approximation checkable from the payload alone — unless the row DECLARES
///   it lands no commit (CLOUD-735), and `declares-no-commit-with-pr` refuses
///   the row that declares that AND carries one, so `none` never becomes the
///   cheapest way past the gate.
/// - `unmilestoned (<column>)`: an unparented started row names its phase.
/// - `child-unmilestoned`: a child of a phased parent carries a phase of its
///   own — the parent's, or a different one DECLARED (CLOUD-599). Carrying none
///   is the refusal; a parent outside the set is unjudgeable.
fn judge_row(
    closure: &Closure<'_>,
    row: &Row<'_>,
    milestones_judgeable: bool,
    judgement: &mut Judgement,
) {
    let vocabulary = closure.vocabulary;
    if row.status == vocabulary.in_progress && !row.assigned {
        judgement.report(&row.id, "in-progress-unassigned");
    }
    if row.status == vocabulary.review {
        let (_, bump) = readiness(closure.grammar, row.value, closure.root);
        let declares_none = bump.as_deref() == Some("none");
        if row.prs == 0 && !declares_none {
            judgement.report(&row.id, "in-review-no-pr");
        }
        if row.prs != 0 && declares_none {
            judgement.report(&row.id, "declares-no-commit-with-pr");
        }
    }
    if !milestones_judgeable {
        return;
    }
    match &row.parent {
        None => {
            if vocabulary.started(&row.status) && !row.milestoned() {
                judgement.report(&row.id, &format!("unmilestoned ({})", row.status));
            }
        }
        Some(parent) => match closure.row(parent) {
            None => judgement.unjudged(
                &row.id,
                &format!("child-milestone-unjudgeable (parent {parent} not in the set)"),
            ),
            Some(found) if found.milestoned() && !row.milestoned() => {
                judgement.report(&row.id, &format!("child-unmilestoned (parent {parent})"));
            }
            Some(_) => {}
        },
    }
}

/// Graph coherence: the relation key is present, every blocker is in the set,
/// and the relation is acyclic. Returns the edges, byte-stably ordered.
///
/// `dangling-blocker` is UNJUDGED and set-keyed (CLOUD-678), never a violation:
/// the tracker keeps `blockedBy` after the blocker completes, so an active-only
/// closure carries an edge to a done ancestor for every landed blocker, and a
/// violation that fires on correct input trains readers to ignore it.
fn judge_edges(closure: &Closure<'_>, judgement: &mut Judgement) -> Vec<(String, String)> {
    let keyless: Vec<&str> = closure
        .rows
        .iter()
        .filter(|row| !row.edges_declared)
        .map(|row| row.id.as_str())
        .collect();
    if !keyless.is_empty() {
        judgement.unjudged(
            SET,
            &format!("unjudgeable-blockedby ({})", keyless.join(" ")),
        );
    }
    let mut edges: Vec<(String, String)> = closure
        .rows
        .iter()
        .flat_map(|row| row.blocked_by.iter().map(|to| (row.id.clone(), to.clone())))
        .collect();
    edges.sort_by(|left, right| {
        by_num(&left.0)
            .cmp(&by_num(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });
    let mut outside: Vec<String> = edges
        .iter()
        .filter(|(_, to)| closure.row(to).is_none())
        .map(|(_, to)| to.clone())
        .collect();
    sort_ids(&mut outside);
    outside.dedup();
    if !outside.is_empty() {
        judgement.unjudged(SET, &format!("dangling-blocker ({})", outside.join(" ")));
    }
    let members = cycle_members(&edges);
    if !members.is_empty() {
        judgement.report(SET, &format!("blockedby-cycle ({})", members.join(" ")));
    }
    edges
}

/// Every id on a `blockedBy` cycle, byte-stably ordered.
///
/// A self-edge is not a cycle, which is `tsort`'s reading of a pair naming one
/// item twice: it declares the item and orders nothing.
fn cycle_members(edges: &[(String, String)]) -> Vec<String> {
    let mut next: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (from, to) in edges {
        if from != to {
            next.entry(from.as_str()).or_default().push(to.as_str());
        }
    }
    let mut members: Vec<String> = next
        .keys()
        .filter(|start| returns_to(&next, start))
        .map(|start| (*start).to_owned())
        .collect();
    sort_ids(&mut members);
    members
}

/// Whether a walk from `start` along the relation comes back to it.
fn returns_to(next: &BTreeMap<&str, Vec<&str>>, start: &str) -> bool {
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut stack: Vec<&str> = next.get(start).cloned().unwrap_or_default();
    while let Some(node) = stack.pop() {
        if node == start {
            return true;
        }
        if seen.insert(node)
            && let Some(more) = next.get(node)
        {
            stack.extend(more.iter().copied());
        }
    }
    false
}

/// Status claims: prose is not a second authority for a column (CLOUD-234).
///
/// THE VOCABULARY IS THE PIPED SET'S OCCUPIED STATUSES, never a second copy of
/// the board's list. A claim is an id-first span whose connective is
/// allowlisted — only punctuation, emphasis and whitespace, optionally one
/// declared present-tense connective, may stand between the key and the column
/// word — because no blocklist of narration verbs ends. Case-sensitive, since
/// the columns are proper nouns the payload spells exactly.
///
/// THE ALPHABET'S OWN ANTI-VACUITY ARM (CLOUD-838): a claim naming a column no
/// piped row occupies never matched the scan above, so a row that LEFT a column
/// was invisible exactly where a stale claim is likeliest. With the connective
/// REQUIRED, a capitalised span that is not in the alphabet is reported
/// could-not-look, keyed to the set; the gloss form of such a claim stays
/// uncovered, because telling `— **Shipped**` from `— **Batten**` needs the
/// second authority over the column list this gate must not hold.
fn judge_claims(closure: &Closure<'_>, judgement: &mut Judgement) {
    let undescribed: Vec<&str> = closure
        .rows
        .iter()
        .filter(|row| row.description.is_none())
        .map(|row| row.id.as_str())
        .collect();
    if !undescribed.is_empty() {
        judgement.unjudged(
            SET,
            &format!("unjudgeable-description ({})", undescribed.join(" ")),
        );
    }
    // A scan whose expressions will not compose judged nothing, which is not the
    // same as finding nothing: it says so, keyed to the set, rather than going
    // quiet.
    let Some(scan) = Scan::build(closure) else {
        judgement.unjudged(
            SET,
            "status-claim-unscannable (the declared expressions do not compose)",
        );
        return;
    };
    for row in &closure.rows {
        let Some(description) = row.description else {
            continue;
        };
        let prose = scan.neutralised(closure.grammar, description);
        scan.against_the_board(closure, row, &prose, judgement);
        scan.outside_the_alphabet(row, &prose, judgement);
    }
}

/// The compiled expressions of one claim scan.
#[derive(Debug)]
struct Scan {
    claim: Regex,
    asserted: Regex,
    alphabet: Regex,
    code_span: Regex,
    quoted: Regex,
}

impl Scan {
    /// `None` only when an expression composed from the declared rows will not
    /// compile — the caller reports that as could-not-look.
    fn build(closure: &Closure<'_>) -> Option<Self> {
        let mut columns: Vec<String> = closure
            .rows
            .iter()
            .map(|row| row.status.clone())
            .filter(|status| !status.is_empty())
            .collect();
        columns.sort();
        columns.dedup();
        // LONGEST FIRST, so the alternation reads a column the way a POSIX
        // longest match did: a column that is a prefix of another must not win.
        columns.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
        let alternation = columns
            .iter()
            .map(|column| regex::escape(column.as_str()))
            .collect::<Vec<_>>()
            .join("|");
        let key = closure.grammar.key_expression();
        let connective = &closure.vocabulary.connective;
        let filler = r"[^[:alnum:]\\]*";
        Some(Self {
            claim: composed(&format!(
                "(?P<key>{key}){filler}(?:(?:{connective}){filler})?(?P<column>{alternation})"
            ))
            .ok()?,
            asserted: composed(&format!(
                "(?P<key>{key}){filler}(?:{connective}){filler}(?P<span>{CAPITALISED})"
            ))
            .ok()?,
            alphabet: composed(&format!("^(?:{alternation})$")).ok()?,
            code_span: composed(CODE_SPAN).ok()?,
            quoted: composed(QUOTED).ok()?,
        })
    }

    /// The body with mention markup stripped and every code span and quoted
    /// phrase neutralised — naming a claim is not making one.
    fn neutralised(&self, grammar: &Grammar, description: &str) -> String {
        let plain = grammar.without_mentions(description);
        let spans = self.code_span.replace_all(&plain, "CODESPAN");
        self.quoted.replace_all(&spans, "QUOTED").into_owned()
    }

    /// Every claim the alphabet can spell, compared against the board.
    fn against_the_board(
        &self,
        closure: &Closure<'_>,
        row: &Row<'_>,
        prose: &str,
        judgement: &mut Judgement,
    ) {
        for line in prose.lines() {
            for found in self.claim.captures_iter(line) {
                let cited = found.name("key").map_or("", |m| m.as_str());
                let claimed = found.name("column").map_or("", |m| m.as_str());
                match closure.row(cited) {
                    // Keyed to the SET: which closure was piped is the caller's
                    // choice, not this row's dishonesty.
                    None => judgement.unjudged(
                        SET,
                        &format!(
                            "status-claim-unjudgeable ({} claims {cited}, not in the piped set)",
                            row.id
                        ),
                    ),
                    Some(actual) if actual.status != claimed => {
                        judgement.report(
                            &row.id,
                            &format!(
                                "status-claim-disagrees ({cited} claimed {claimed}, board says {})",
                                actual.status
                            ),
                        );
                    }
                    Some(_) => {}
                }
            }
        }
    }

    /// Every asserted claim naming a word outside the alphabet.
    fn outside_the_alphabet(&self, row: &Row<'_>, prose: &str, judgement: &mut Judgement) {
        for line in prose.lines() {
            for found in self.asserted.captures_iter(line) {
                let token = found.name("span").map_or("", |m| m.as_str());
                // In the alphabet: the scan above already judged it, and one claim
                // gets one rule id, never two.
                if token.is_empty() || self.alphabet.is_match(token) {
                    continue;
                }
                let cited = found.name("key").map_or("", |m| m.as_str());
                let unscannable = format!(
                    "status-claim-unscannable ({} claims {cited} is {token}, which no piped issue \
                     occupies — pipe one that does)",
                    row.id
                );
                judgement.unjudged(SET, &unscannable);
            }
        }
    }
}

/// The frontier and every exclusion from it, each attributed (CLOUD-251).
///
/// A ready-queue row is on the frontier iff its own payload passes the Ready gate
/// and every blocker in the set is settled. The three arms end in three places:
/// an unready row is `todo-not-ready`, a violation (CLOUD-375 — the queue is
/// lying); a row the gate could not read is unjudged; an unsettled blocker is a
/// note, because that is scheduling and the row is not claiming otherwise. A
/// blocker outside the set is unjudged and never a note (CLOUD-678): "excluded"
/// reads exactly like a legitimate block, and an empty frontier reads as
/// "nothing is ready".
fn judge_frontier(closure: &Closure<'_>, edges: &[(String, String)], judgement: &mut Judgement) {
    for row in &closure.rows {
        if row.status != closure.vocabulary.ready {
            continue;
        }
        match readiness(closure.grammar, row.value, closure.root).0 {
            Readiness::Ready => {}
            Readiness::Unready(lines) => {
                judgement.report(&row.id, "todo-not-ready");
                judgement.lines.extend(lines);
                continue;
            }
            Readiness::Unjudgeable => {
                judgement.unjudged(&row.id, "excluded (unjudgeable-ready-block)");
                continue;
            }
        }
        let mut blocking = String::new();
        let mut unknown = String::new();
        let mut retired = String::new();
        for (_, to) in edges.iter().filter(|(from, _)| *from == row.id) {
            let Some(blocker) = closure.row(to) else {
                unknown.push(' ');
                unknown.push_str(to);
                continue;
            };
            if closure.settled(blocker) {
                if closure.retired(blocker) {
                    retired.push(' ');
                    retired.push_str(to);
                }
            } else {
                blocking.push(' ');
                blocking.push_str(to);
            }
        }
        if unknown.is_empty() && blocking.is_empty() {
            judgement.frontier.push(row.id.clone());
            // CLOUD-477's second decision: schedulable, AND the reason on the
            // record — a cancelled blocker may have taken the premise with it.
            if !retired.is_empty() {
                judgement.note(&row.id, &format!("frontier-over-retired-blocker{retired}"));
            }
        } else if unknown.is_empty() {
            judgement.note(&row.id, &format!("excluded (blocked-by{blocking})"));
        } else {
            judgement.unjudged(
                &row.id,
                &format!("excluded (unjudgeable-blocker{unknown}{blocking})"),
            );
        }
    }
}

/// Render the graph's judgement, and mint the move receipts on a coherent board.
fn graph(
    set: &[Value],
    declared: &Declared<'_>,
    now: u64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let vocabulary = Vocabulary::resolve(declared.board, declared.patterns)?;
    let Some(judgement) = judge(set, declared.grammar, &vocabulary, declared.root) else {
        writeln!(
            err,
            "::error:: board check: stdin is not a set of get_issue payloads (need id and status per issue)"
        )?;
        return Ok(ExitCode::Internal);
    };
    for line in &judgement.lines {
        writeln!(err, "{line}")?;
    }
    writeln!(out, "wip {}", judgement.wip)?;
    for id in &judgement.frontier {
        writeln!(out, "frontier {id}")?;
    }
    if judgement.violations > 0 {
        writeln!(
            err,
            "::error:: board check: {} violation(s) — the board is signalling falsely",
            judgement.violations
        )?;
    }
    // COULD-NOT-LOOK OUTRANKS A VIOLATION HERE (CLOUD-251): a verdict over a set
    // this could only partly read is not a verdict.
    if judgement.unjudgeable > 0 {
        writeln!(
            err,
            "::error:: board check: {} payload(s) could not be judged — re-fetch with the \
             relations, attachments, milestones and descriptions included",
            judgement.unjudgeable
        )?;
        return Ok(ExitCode::Internal);
    }
    if judgement.violations > 0 {
        return Ok(ExitCode::Violation);
    }
    mint_receipts(declared, &judgement.ids, now);
    writeln!(
        out,
        "board check: board coherent ({} issues)",
        judgement.ids.len()
    )?;
    Ok(ExitCode::Success)
}

//MUTANT receipt-carries-no-ids|s@^        if declared.grammar.key_of(id).is_none() {$@        if true {@|a_coherent_board_records_one_receipt_per_id_it_judged
//MUTANT receipt-mints-any-value|s@^        if declared.grammar.key_of(id).is_none() {$@        if false {@|a_value_that_is_not_an_issue_key_mints_nothing_so_it_cannot_become_a_path

/// One receipt per judged id, the trigger a move guard reads (CLOUD-512).
///
/// MINTED ONLY ON THE SUCCESS PATH: a board carrying violations must not
/// authorise a move. ONE FILE PER ID, because a bare "the board was checked"
/// receipt is satisfied by judging one clean row and then sweeping fifteen.
/// REPLACED rather than appended, so the file's age is the freshest
/// adjudication of that one id. An id that is not an issue key mints nothing —
/// it would otherwise become a file name. FAIL-SOFT: a receipt that cannot be
/// written must not turn a coherent board into a failing one.
///
/// The git directory is the CURRENT checkout's, never the common one: a linked
/// worktree's guard reads its own store.
fn mint_receipts(declared: &Declared<'_>, ids: &[String], now: u64) {
    let Some(check) = declared
        .board
        .and_then(|board| board.move_receipt.as_deref())
    else {
        return;
    };
    let Ok(git_dir) = crate::git::git_dir(Path::new(".")) else {
        return;
    };
    let store = git_dir.join("batten-receipts");
    if std::fs::create_dir_all(&store).is_err() {
        return;
    }
    for id in ids {
        if declared.grammar.key_of(id).is_none() {
            continue;
        }
        let _ =
            crate::durable::replace(store.join(format!("{check}.{id}")), format!("{now} {id}\n"));
    }
}

// --- the payloads' citations against the tree (`--cites`) ---------------------

/// What `--cites` reads, resolved.
#[derive(Debug)]
struct Cites {
    obligations: Regex,
    cited_test: Regex,
    cited_path: Regex,
    corpus: Vec<crate::rules::Selector>,
    exclude: Vec<crate::rules::Selector>,
    prospective: Option<String>,
}

/// What `--cites` found.
#[derive(Debug, Default)]
struct Tally {
    findings: Vec<String>,
    notes: Vec<String>,
    cited: usize,
    resolved: usize,
    prospective: usize,
    history: bool,
}

//MUTANT fixtures-satisfy-a-citation|s@^        let drop = &self.exclude;$@        let drop: \&[crate::rules::Selector] = \&[];@|a_citation_that_resolves_only_in_a_fixture_and_nowhere_else_is_refused
//MUTANT superseded-block-is-judged|s@^            start = Some(at);$@            start = start.or(Some(at));@|the_last_opener_is_the_live_block_and_an_earlier_one_is_history
//MUTANT marker-not-required|s@^            if marked {$@            if true {@|an_unmarked_absent_path_is_still_refused
//MUTANT marker-outranks-history|s@^                if deleted == Some(true) {$@                if false {@|a_marker_on_a_deleted_path_is_refused_not_believed

impl Cites {
    fn resolve(declared: &Declared<'_>) -> Result<Self> {
        let board = declared.board.ok_or_else(|| undeclared("board"))?;
        if board.cites_corpus.is_empty() {
            return Err(undeclared("board.cites_corpus"));
        }
        Ok(Self {
            obligations: declared_row(declared.patterns, OBLIGATIONS_LABEL)?,
            cited_test: declared_row(declared.patterns, CITED_TEST)?,
            cited_path: declared_row(declared.patterns, CITED_PATH)?,
            corpus: selectors(&board.cites_corpus)?,
            exclude: selectors(&board.cites_exclude)?,
            prospective: board.cites_prospective.clone(),
        })
    }

    /// Judge every payload's LIVE Ready block against the tree.
    ///
    /// `Err` is could-not-look: a set that is not payloads carrying a body, or a
    /// tree that cannot be enumerated or holds nothing to resolve against.
    fn judge(&self, set: &[Value], declared: &Declared<'_>) -> std::result::Result<Tally, String> {
        let well_formed = !set.is_empty()
            && set.iter().all(|value| {
                value
                    .as_object()
                    .is_some_and(|o| o.contains_key("description"))
            });
        if !well_formed {
            return Err(
                "stdin is not a get_issue payload (need a description per issue)".to_owned(),
            );
        }
        let drop = &self.exclude;
        let paths = corpus_paths(declared.root, &self.corpus, drop)?;
        if paths.is_empty() {
            return Err(
                "no tracked file matches the declared corpus — a citation cannot be resolved \
                 against an empty corpus"
                    .to_owned(),
            );
        }
        let contents: Vec<String> = paths
            .iter()
            .filter_map(|path| std::fs::read(declared.root.join(path)).ok())
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .collect();
        let mut tally = Tally {
            history: !crate::git::is_shallow(declared.root).unwrap_or(true),
            ..Tally::default()
        };
        for value in set {
            let Some(key) = value.get("id").filter(|id| present(id)).map(scalar) else {
                continue;
            };
            let body = set
                .iter()
                .find(|candidate| candidate.get("id").map(scalar).as_deref() == Some(key.as_str()))
                .and_then(|found| found.get("description"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Some(block) = live_block(declared.grammar.opener(), body) else {
                continue;
            };
            self.tests_in(
                &key,
                &block,
                declared.grammar.clause_label(),
                &contents,
                &mut tally,
            );
            self.paths_in(&key, &block, declared.root, &mut tally);
        }
        tally.findings.sort();
        tally.notes.sort();
        Ok(tally)
    }

    /// Cited test names, inside the obligations clause only — a greedier span
    /// would read an unrelated backticked symbol in a later clause as an
    /// obligation.
    fn tests_in(
        &self,
        key: &str,
        block: &[&str],
        clause: &Regex,
        contents: &[String],
        tally: &mut Tally,
    ) {
        let Some(start) = block
            .iter()
            .position(|line| self.obligations.is_match(line))
        else {
            return;
        };
        let end = block
            .iter()
            .skip(start + 1)
            .position(|line| clause.is_match(line))
            .map_or(block.len(), |next| start + 1 + next);
        let span = block.get(start..end).unwrap_or_default().join("\n");
        let tokens: BTreeSet<&str> = self
            .cited_test
            .find_iter(&span)
            .map(|found| found.as_str().trim_matches('`'))
            .collect();
        for token in tokens {
            tally.cited += 1;
            if contents.iter().any(|text| text.contains(token)) {
                tally.resolved += 1;
            } else {
                tally
                    .findings
                    .push(format!("{key} {token} absent-cited-test"));
            }
        }
    }

    /// Cited paths, anywhere in the live block — three answers, not two
    /// (CLOUD-920): it exists, it is marked prospective, or it is refused.
    fn paths_in(&self, key: &str, block: &[&str], root: &Path, tally: &mut Tally) {
        let text = block.join("\n");
        let paths: BTreeSet<&str> = self
            .cited_path
            .find_iter(&text)
            .map(|found| found.as_str().trim_matches('`'))
            .filter(|path| path.contains('/'))
            .collect();
        for path in paths {
            tally.cited += 1;
            if root.join(path).exists() {
                tally.resolved += 1;
                continue;
            }
            // The marker is matched WITH its path, so one marker elsewhere in the
            // block cannot excuse every citation in it.
            let marked = self
                .prospective
                .as_deref()
                .is_some_and(|marker| text.contains(&format!("`{path}` {marker}")));
            if marked {
                // THE ANTI-FORGERY TERM: history may REFUTE a marker — a path an
                // ancestor deleted was present — and is never asked to grant one.
                let deleted = if tally.history {
                    crate::git::path_was_deleted(root, path).ok().flatten()
                } else {
                    None
                };
                if deleted == Some(true) {
                    tally
                        .findings
                        .push(format!("{key} {path} stale-cited-path"));
                } else {
                    tally.prospective += 1;
                    tally
                        .notes
                        .push(format!("{key} {path} prospective-cited-path"));
                }
            } else {
                tally
                    .findings
                    .push(format!("{key} {path} absent-cited-path"));
            }
        }
    }
}

/// The LIVE Ready block: from the LAST opener to the end (CLOUD-826).
///
/// The refinement gate takes the FIRST opener and this takes the LAST, and the
/// difference is stated rather than left implicit: a body may carry a superseded
/// block kept so a reader can see which clauses went stale, and a superseded
/// clause carries no obligation. A body with no opener is not this gate's
/// business — the refinement gate already reports it.
fn live_block<'a>(opener: &Regex, body: &'a str) -> Option<Vec<&'a str>> {
    let lines: Vec<&str> = body.lines().collect();
    let mut start = None;
    for (at, line) in lines.iter().enumerate() {
        if opener.is_match(line) {
            start = Some(at);
        }
    }
    Some(lines.get(start?..).unwrap_or_default().to_vec())
}

impl Tally {
    /// Render, and say whether a citation was refused.
    ///
    /// Notes print before the verdict and on stderr either way: a prospective
    /// citation is information about a correct block and must neither move the
    /// exit code nor be buried under a refusal after it.
    fn render(&self, out: &mut dyn Write, err: &mut dyn Write) -> Result<bool> {
        for note in &self.notes {
            writeln!(err, "  {note}")?;
        }
        if !self.notes.is_empty() && !self.history {
            writeln!(
                err,
                "::notice:: board check --cites: {} prospective citation(s) above, and this clone is \
                 SHALLOW — so a prospective marker could not be checked against history. A marker on \
                 a path that was deleted rather than never written is not detectable here; a full \
                 clone can check it.",
                self.prospective
            )?;
        }
        if !self.findings.is_empty() {
            writeln!(
                err,
                "::error:: board check --cites: a Ready block cites something the tree does not \
                 carry. This checks EXISTENCE, never relevance — whether a test that exists is the \
                 right test is not computable (CLOUD-93). A citation resolving only in an excluded \
                 path is refused, because a fixture quoting the citation is not the thing cited:"
            )?;
            for finding in &self.findings {
                writeln!(err, "  {finding}")?;
            }
            writeln!(
                err,
                "::error:: board check --cites: {} of {} citation(s) resolve nothing",
                self.findings.len(),
                self.cited
            )?;
            return Ok(true);
        }
        if self.prospective > 0 {
            writeln!(
                out,
                "board check --cites: {} of {} citation(s) resolve against the tree; {} prospective",
                self.resolved, self.cited, self.prospective
            )?;
        } else {
            writeln!(
                out,
                "board check --cites: {} of {} citation(s) resolve against the tree",
                self.resolved, self.cited
            )?;
        }
        Ok(false)
    }
}

// --- the tree's clause citations against the payloads (`--refs`) --------------

/// What `--refs` reads, resolved.
#[derive(Debug)]
struct Refs {
    citation: Regex,
    tag: Regex,
    exclude: Vec<crate::rules::Selector>,
}

/// One clause citation in the tree: where, which issue, which clause.
type Hit = (String, usize, String, String);

/// What `--refs` found.
#[derive(Debug, Default)]
struct Found {
    findings: Vec<String>,
    gaps: Vec<String>,
    hits: usize,
}

//MUTANT clause-always-present|s@^            } else if !carried.contains(clause.as_str()) {$@            } else if false {@|a_citation_naming_a_clause_the_issue_does_not_carry_is_reported_with_its_pointer
//MUTANT unfetched-issue-passes|s@^            if body.is_empty() {$@            if false {@|a_cited_issue_absent_from_the_payload_set_is_could_not_look_never_a_silent_pass

impl Refs {
    fn resolve(declared: &Declared<'_>) -> Result<Self> {
        let exclude = declared
            .board
            .map(|board| selectors(&board.refs_exclude))
            .transpose()?
            .unwrap_or_default();
        // THE KEY IS THE GRAMMAR'S, composed in front of the citation's tail, so
        // the issue key keeps its one definition here too.
        let tail = declared_row(declared.patterns, CLAUSE_CITATION)?;
        let key = declared.grammar.key_expression();
        Ok(Self {
            citation: composed(&format!("(?P<key>{key})(?:{})", tail.as_str()))?,
            tag: declared_row(declared.patterns, CLAUSE_TAG)?,
            exclude,
        })
    }

    /// Every clause citation in the tracked tree, deduplicated and ordered.
    ///
    /// A file carrying a NUL byte is binary and skipped, `grep -I`'s reading.
    fn hits(&self, root: &Path) -> std::result::Result<BTreeSet<Hit>, String> {
        let everything = [crate::rules::Selector::new("**")
            .map_err(|_| "the whole-tree glob does not compile".to_owned())?];
        let mut hits = BTreeSet::new();
        for path in corpus_paths(root, &everything, &self.exclude)? {
            let Ok(bytes) = std::fs::read(root.join(&path)) else {
                continue;
            };
            if bytes.contains(&0) {
                continue;
            }
            let text = String::from_utf8_lossy(&bytes);
            for (at, line) in text.lines().enumerate() {
                for found in self.citation.captures_iter(line) {
                    let key = found.name("key").map_or("", |m| m.as_str());
                    let clause = found.name("clause").map_or("", |m| m.as_str());
                    if key.is_empty() || clause.is_empty() {
                        continue;
                    }
                    hits.insert((path.clone(), at + 1, key.to_owned(), clause.to_owned()));
                }
            }
        }
        Ok(hits)
    }

    /// Judge every clause citation in the tree against the piped bodies.
    ///
    /// REFUTES, NEVER CONFIRMS: a sparse clause set is not a defect, a citation
    /// of a clause that is not there is. A cited issue absent from the set is a
    /// GAP, never a pass — an unfetched issue looks exactly like a clean one.
    fn judge(&self, set: &[Value], declared: &Declared<'_>) -> std::result::Result<Found, String> {
        let well_formed = !set.is_empty()
            && set.iter().all(|value| {
                value
                    .as_object()
                    .is_some_and(|o| o.contains_key("id") && o.contains_key("description"))
            });
        if !well_formed {
            return Err(
                "stdin is not a set of get_issue payloads (need id and description per issue)"
                    .to_owned(),
            );
        }
        let grammar = declared.grammar;
        let mut found = Found::default();
        for (path, line, key, clause) in self.hits(declared.root)? {
            found.hits += 1;
            let body = set
                .iter()
                .find(|value| value.get("id").map(scalar).as_deref() == Some(key.as_str()))
                .and_then(|value| value.get("description"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let body_lines: Vec<&str> = body.lines().collect();
            let carried = declared_clauses(&body_lines, grammar, &self.tag);
            if body.is_empty() {
                found
                    .gaps
                    .push(format!("{path}:{line} {key} unjudgeable-issue"));
            } else if !carried.contains(clause.as_str()) {
                found
                    .findings
                    .push(format!("{path}:{line} {key} §{clause} absent-issue-clause"));
            }
        }
        Ok(found)
    }
}

/// Every clause number a body DECLARES: each tag on each clause-label line.
///
/// OVER-DECLARING IS THE SAFE DIRECTION: a label naming two numbers — one its
/// tag, one a cross-reference — declares both, which can only make this report
/// LESS. A guard with false positives gets bypassed.
fn declared_clauses<'a>(lines: &[&'a str], grammar: &Grammar, tag: &Regex) -> BTreeSet<&'a str> {
    lines
        .iter()
        .copied()
        .filter(|line| grammar.clause_label().is_match(line))
        .flat_map(|line| tag.captures_iter(line))
        .filter_map(|found| found.name("clause").map(|m| m.as_str()))
        .collect()
}

impl Found {
    /// Render, and say (refused, could-not-look).
    fn render(&self, out: &mut dyn Write, err: &mut dyn Write) -> Result<(bool, bool)> {
        if !self.gaps.is_empty() {
            writeln!(
                err,
                "::error:: board check --refs: cited issues are absent from the piped payload set, \
                 so their citations could not be judged. Fetch them and pipe again — an unfetched \
                 issue looks exactly like a clean one (CLOUD-189):"
            )?;
            for gap in &self.gaps {
                writeln!(err, "  {gap}")?;
            }
        }
        if !self.findings.is_empty() {
            writeln!(
                err,
                "::error:: board check --refs: citations name a clause their issue does not carry. \
                 Cite the clause that holds the content, or the issue's own clause if it moved \
                 (CLOUD-809):"
            )?;
            for finding in &self.findings {
                writeln!(err, "  {finding}")?;
            }
        }
        if self.gaps.is_empty() && self.findings.is_empty() {
            writeln!(
                out,
                "board check --refs: every clause citation in the tree resolves ({} checked)",
                self.hits
            )?;
        }
        Ok((!self.findings.is_empty(), !self.gaps.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::{by_num, cycle_members, payload_set};

    #[test]
    fn an_array_and_a_stream_are_one_set() {
        let array = payload_set(r#"[{"id":"A-1"},{"id":"A-2"}]"#).unwrap_or_default();
        let stream = payload_set("{\"id\":\"A-1\"}\n{\"id\":\"A-2\"}").unwrap_or_default();
        assert_eq!(array, stream);
        assert_eq!(array.len(), 2);
    }

    #[test]
    fn unparseable_input_is_no_set_at_all() {
        assert!(payload_set("not json").is_none());
    }

    #[test]
    fn ordering_is_numeric_not_lexical() {
        let mut ids = vec!["A-10".to_owned(), "A-9".to_owned(), "A-100".to_owned()];
        ids.sort_by(|left, right| by_num(left).cmp(&by_num(right)));
        assert_eq!(ids, ["A-9", "A-10", "A-100"]);
    }

    #[test]
    fn a_cycle_names_its_members_and_a_self_edge_is_not_one() {
        let edge = |from: &str, to: &str| (from.to_owned(), to.to_owned());
        assert_eq!(
            cycle_members(&[edge("A-1", "A-2"), edge("A-2", "A-1"), edge("A-3", "A-1")]),
            ["A-1", "A-2"]
        );
        assert!(cycle_members(&[edge("A-1", "A-1"), edge("A-2", "A-1")]).is_empty());
    }
}
