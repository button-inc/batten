//! The board's dependency graph is coherent, and every started row is honestly
//! labelled (CLOUD-175, ported off `mise-tasks/graph-check.sh` by CLOUD-1221).
//!
//! The board is the observability surface the whole workflow contract leans on,
//! so a column that signals falsely is exactly the kind of wrong completion
//! signal this crate exists to catch. This module decides that over a SET of
//! `get_issue` payloads, and emits the ready frontier as a by-product: every
//! agent computing it from the same set gets the same answer, which is what
//! replaces a dispatcher.
//!
//! # One Ready grammar, not two
//!
//! `todo-not-ready` and the `bump` fact both ask [`crate::ready::lint`] in
//! process. The program this replaces spawned `mise-tasks/ready-lint.sh`, a
//! second copy of the grammar that had already drifted from the compiled one —
//! CLOUD-1092's `bump no-release` split landed in the crate and never reached
//! the board. Composing the predicate rather than copying it is the whole row.
//!
//! # Three channels, and the order they outrank each other in (CLOUD-251)
//!
//! A line is one of three things, and collapsing any two was a measured defect:
//!
//! | channel | meaning | verb exit |
//! | --- | --- | --- |
//! | violation | the board is signalling falsely | `2` |
//! | unjudged | the caller did not pipe enough to judge | `1`, and it OUTRANKS a violation |
//! | note | an honest frontier exclusion | unmoved |
//!
//! Could-not-look outranks a violation because the caller's next action is a
//! re-fetch, after which more violations may appear; answering "your board is
//! wrong" first sends them to fix a board over a question never fully asked.
//! Both report sets print before either exit, so one never hides the other.
//!
//! # Pointer-only (rule 4)
//!
//! Every line is an issue key, a rule id, and column names or keys. No byte of a
//! description reaches the output: the status-claim scan reports the ids and the
//! column words it compared, never the sentence they were found in.
//!
//! # The consumer's words, never the crate's (rule 1)
//!
//! Issue keys come from the `ready-issue-key` row, mention markup from
//! `ready-issue-mention-markup`, the claim connective from
//! `graph-status-claim-connective`, and the three columns this reads by NAME from
//! `[board]`. The payload's `statusType` values are the tracker's schema — read
//! like `relations.blockedBy` — rather than a consumer's vocabulary.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use regex::Regex;

use crate::Result;
use crate::board::Columns;
use crate::error::UsageError;
use crate::ready::{Grammar, Payload};

/// The `[[pattern]]` row carrying the status-claim connective.
///
/// Named once, so the refusal that says it is missing and the lookup that
/// reads it cannot drift apart.
pub const CONNECTIVE_PATTERN: &str = "graph-status-claim-connective";

/// Everything the decision reads that is not the payload set.
#[derive(Debug)]
pub struct Vocabulary<'a> {
    /// The one Ready grammar.
    pub grammar: &'a Grammar,
    /// The ready queue's column name.
    pub ready: &'a str,
    /// The pulled column's name.
    pub in_progress: &'a str,
    /// The landed column's name.
    pub review: &'a str,
    /// The present-tense connective that turns a mention into a claim.
    pub connective: &'a Regex,
    /// Where the grammar's tree-reading clauses resolve — the consumer's root.
    pub root: &'a Path,
}

impl<'a> Vocabulary<'a> {
    /// Resolve the three columns this reads, or say which one is undeclared.
    ///
    /// # Errors
    ///
    /// [`UsageError`] naming the first `[board]` key the consumer has not
    /// declared — could-not-look, never a column guessed for them.
    pub fn resolve(
        grammar: &'a Grammar,
        columns: &'a Columns,
        connective: &'a Regex,
        root: &'a Path,
    ) -> Result<Self> {
        let undeclared =
            |gap: crate::board::Undeclared| UsageError::raise(format!("graph check: {gap}"));
        Ok(Self {
            grammar,
            ready: columns.ready().map_err(undeclared)?,
            in_progress: columns.in_progress().map_err(undeclared)?,
            review: columns.review().map_err(undeclared)?,
            connective,
            root,
        })
    }
}

/// Compile the connective row, or refuse naming it.
///
/// # Errors
///
/// [`UsageError`] when the consumer declares no such row, or it will not
/// compile. A claim scan with no connective would judge nothing and report
/// clean, which is the dead-gate shape rule 1's registry exists to make loud.
pub fn connective(patterns: &[crate::pattern::NamedPattern]) -> Result<Regex> {
    let Some(row) = patterns.iter().find(|row| row.id == CONNECTIVE_PATTERN) else {
        return Err(UsageError::raise(format!(
            "graph check: this repository declares no `[[pattern]]` row `{CONNECTIVE_PATTERN}`, \
             so a status claim cannot be told from a mention — the scan could not look, which \
             is not the same as finding no claim"
        )));
    };
    Regex::new(&row.regex).map_err(|_| {
        UsageError::raise(format!(
            "graph check: the `[[pattern]]` row `{CONNECTIVE_PATTERN}` does not compile as a \
             regular expression"
        ))
    })
}

/// Read a payload set: a JSON array, or a concatenated stream of objects.
///
/// # Errors
///
/// [`UsageError`] when the input is not a non-empty set of objects each
/// carrying `id` and `status` — could-not-look, distinct from a failing board.
pub fn parse(text: &str) -> Result<Vec<serde_json::Value>> {
    let refusal = || {
        UsageError::raise(
            "graph check: stdin is not a set of get_issue payloads (need id and status per issue)"
                .to_owned(),
        )
    };
    let mut values = Vec::new();
    for value in serde_json::Deserializer::from_str(text).into_iter::<serde_json::Value>() {
        values.push(value.map_err(|_| refusal())?);
    }
    let rows = match values.as_slice() {
        [serde_json::Value::Array(items)] => items.clone(),
        _ => values,
    };
    let complete = !rows.is_empty()
        && rows
            .iter()
            .all(|row| row.get("id").is_some() && row.get("status").is_some());
    if complete { Ok(rows) } else { Err(refusal()) }
}

/// What one run found, in the order it found it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Every stderr line, in emission order: violations, unjudged lines and
    /// notes interleaved exactly as the rows were walked.
    pub reports: Vec<String>,
    /// The ready frontier, in key order.
    pub frontier: Vec<String>,
    /// How many rows sit in the pulled column.
    pub wip: usize,
    /// How many lines said the board is signalling falsely.
    pub violations: usize,
    /// How many said the set could not be judged.
    pub unjudgeable: usize,
    /// Every id the set carried, in key order — the receipt subjects.
    pub judged: Vec<String>,
}

impl Outcome {
    fn violation(&mut self, id: &str, rule: &str) {
        self.reports.push(format!("{id} {rule}"));
        self.violations += 1;
    }

    fn unjudged(&mut self, id: &str, rule: &str) {
        self.reports.push(format!("{id} {rule}"));
        self.unjudgeable += 1;
    }

    fn note(&mut self, id: &str, rule: &str) {
        self.reports.push(format!("{id} {rule}"));
    }

    /// A line forwarded verbatim from the Ready grammar, which moves no count:
    /// the `todo-not-ready` beside it already did.
    fn forward(&mut self, line: String) {
        self.reports.push(line);
    }
}

/// The byte-stable ordering every list here uses: numeric by the digits after a
/// key's first `-`, then the whole string.
///
/// `sort -t- -k2,2n`'s ordering, kept so a caller diffing a run from the
/// program this replaces reads an unchanged sequence. `CLOUD-10` after
/// `CLOUD-9`, which a lexical sort gets backwards.
fn by_number(a: &str, b: &str) -> std::cmp::Ordering {
    let number = |text: &str| -> u64 {
        text.split_once('-')
            .map(|(_, rest)| rest)
            .unwrap_or_default()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0)
    };
    number(a).cmp(&number(b)).then_with(|| a.cmp(b))
}

fn sorted(mut items: Vec<String>) -> Vec<String> {
    items.sort_by(|a, b| by_number(a, b));
    items
}

fn text(value: &serde_json::Value) -> String {
    value
        .as_str()
        .map_or_else(|| value.to_string(), ToOwned::to_owned)
}

fn field<'v>(row: &'v serde_json::Value, key: &str) -> Option<&'v serde_json::Value> {
    row.get(key).filter(|value| !value.is_null())
}

/// One payload's fields, read once.
struct Row<'v> {
    id: String,
    status: String,
    status_type: String,
    assigned: bool,
    pull_requests: usize,
    milestoned: bool,
    parent: Option<String>,
    payload: &'v serde_json::Value,
}

impl<'v> Row<'v> {
    fn read(payload: &'v serde_json::Value) -> Self {
        let pull_requests = payload
            .get("attachments")
            .and_then(serde_json::Value::as_array)
            .map_or(0, |items| {
                items
                    .iter()
                    .filter_map(|item| item.get("url").and_then(serde_json::Value::as_str))
                    .filter(|url| crate::landed::is_pull_request_url(url))
                    .count()
            });
        Self {
            id: payload.get("id").map(text).unwrap_or_default(),
            status: payload.get("status").map(text).unwrap_or_default(),
            status_type: field(payload, "statusType").map(text).unwrap_or_default(),
            assigned: field(payload, "assigneeId").is_some(),
            pull_requests,
            milestoned: field(payload, "projectMilestone").is_some(),
            parent: field(payload, "parentId").map(text),
            payload,
        }
    }
}

/// The set, indexed once (CLOUD-634's indexing, kept).
struct Board<'v> {
    rows: Vec<Row<'v>>,
    by_id: BTreeMap<String, usize>,
}

impl<'v> Board<'v> {
    fn new(payloads: &'v [serde_json::Value]) -> Self {
        let mut rows: Vec<Row<'v>> = payloads.iter().map(Row::read).collect();
        rows.sort_by(|a, b| by_number(&a.id, &b.id));
        let by_id = rows
            .iter()
            .enumerate()
            .map(|(at, row)| (row.id.clone(), at))
            .collect();
        Self { rows, by_id }
    }

    fn get(&self, id: &str) -> Option<&Row<'v>> {
        self.by_id.get(id).map(|at| &self.rows[*at])
    }

    fn contains(&self, id: &str) -> bool {
        self.by_id.contains_key(id)
    }

    fn ids(&self) -> Vec<String> {
        self.rows.iter().map(|row| row.id.clone()).collect()
    }
}

/// Is this blocker settled? (CLOUD-477.)
///
/// One test per line, so each arm is separately mutable. `Canceled` and
/// `Duplicate` are two distinct types, measured; the landed column STAYS
/// name-based because its type is `started`, the same type the pulled column
/// carries, so a type-only rule would starve every row behind landed work.
fn blocker_resolved(board: &Board<'_>, words: &Vocabulary<'_>, id: &str) -> bool {
    let Some(row) = board.get(id) else {
        return false;
    };
    let kind = row.status_type.as_str();
    if kind == "completed" {
        return true;
    }
    if kind == "canceled" {
        return true;
    }
    if kind == "duplicate" {
        return true;
    }
    if row.status == words.review {
        return true;
    }
    false
}

/// What this row's §6 declares, from the one grammar's `bump` emission.
///
/// A row whose lint cannot run reads as "did not say", which leaves
/// `in-review-no-pr` deciding exactly as it would without the declaration:
/// could-not-look must not manufacture an exemption.
fn bump_of(words: &Vocabulary<'_>, row: &Row<'_>) -> String {
    let Ok(payload) = Payload::parse(row.payload) else {
        return String::new();
    };
    let Ok(report) = crate::ready::lint(words.grammar, &payload, words.root) else {
        return String::new();
    };
    report
        .emissions
        .iter()
        .find_map(|line| line.strip_prefix("bump ").map(ToOwned::to_owned))
        .unwrap_or_default()
}

/// Decide the whole set.
#[must_use]
pub fn check(payloads: &[serde_json::Value], words: &Vocabulary<'_>) -> Outcome {
    let board = Board::new(payloads);
    let mut out = Outcome {
        judged: board.ids(),
        ..Outcome::default()
    };
    // THE ORDER IS THE REPORT'S ORDER, which `released` and the parity run read:
    // row rules, graph coherence, status claims, then the frontier.
    row_rules(&board, words, payloads, &mut out);
    let edges = coherence(&board, payloads, &mut out);
    status_claims(&board, words, payloads, &mut out);
    frontier(&board, words, &edges, &mut out);
    out.wip = board
        .rows
        .iter()
        .filter(|row| row.status == words.in_progress)
        .count();
    out
}

/// The rules each row answers on its own: assignment, the declared-no-commit
/// exemption, and the milestone claim (CLOUD-695, CLOUD-599, CLOUD-771).
fn row_rules(
    board: &Board<'_>,
    words: &Vocabulary<'_>,
    payloads: &[serde_json::Value],
    out: &mut Outcome,
) {
    let started = |status: &str| {
        status == words.ready || status == words.in_progress || status == words.review
    };

    // THE MILESTONE CLAIM'S ANTI-VACUITY ARM (CLOUD-695), decided over the SET: the
    // tracker omits `projectMilestone` rather than nulling it, so on one payload
    // "none" and "projected away" are the same bytes. If no row anywhere carries
    // the key, the caller projected it away.
    let started_ids: Vec<String> = board
        .rows
        .iter()
        .filter(|row| started(&row.status))
        .map(|row| row.id.clone())
        .collect();
    let mut milestone_judgeable = true;
    if !started_ids.is_empty()
        && !payloads
            .iter()
            .any(|row| row.get("projectMilestone").is_some())
    {
        milestone_judgeable = false;
        out.unjudged(
            "graph",
            &format!("unjudgeable-milestone ({})", sorted(started_ids).join(" ")),
        );
    }

    for row in &board.rows {
        if row.status == words.in_progress && !row.assigned {
            out.violation(&row.id, "in-progress-unassigned");
        }
        // A ROW THAT DECLARES IT LANDS NO COMMIT IS EXEMPT (CLOUD-735), and one that
        // declares that AND carries a PR is refused for the contradiction — the
        // anti-cheat, without which `none` is the cheapest way past this gate.
        if row.status == words.review {
            let declares_none = bump_of(words, row) == "none";
            if row.pull_requests == 0 && !declares_none {
                out.violation(&row.id, "in-review-no-pr");
            }
            if row.pull_requests != 0 && declares_none {
                out.violation(&row.id, "declares-no-commit-with-pr");
            }
        }
        // CLOUD-695 widened by CLOUD-771: an UNPARENTED started row carries a phase.
        // The rule id names the column, since one id over three columns would read
        // as a lie on the other two.
        if milestone_judgeable && row.parent.is_none() && started(&row.status) && !row.milestoned {
            out.violation(&row.id, &format!("unmilestoned ({})", row.status));
        }
        // CLOUD-599: a child inherits its parent's phase unless it declares
        // another. PRESENCE, never identity — both the same-milestone and the
        // different-milestone arms pass, so only "carries none" can refuse.
        if milestone_judgeable && let Some(parent) = &row.parent {
            if !board.contains(parent) {
                out.unjudged(
                    &row.id,
                    &format!("child-milestone-unjudgeable (parent {parent} not in the set)"),
                );
            } else if board.get(parent).is_some_and(|p| p.milestoned) && !row.milestoned {
                out.violation(&row.id, &format!("child-unmilestoned (parent {parent})"));
            }
        }
    }
}

/// The set's graph: whether it can be judged, what it points outside itself at,
/// and whether it cycles. Returns the edges the frontier walks.
fn coherence(
    board: &Board<'_>,
    payloads: &[serde_json::Value],
    out: &mut Outcome,
) -> Vec<(String, String)> {
    // --- graph coherence -------------------------------------------------------
    //
    // ANTI-VACUITY FIRST (CLOUD-251): an ABSENT `blockedBy` is unjudgeable, an
    // empty one is data. Set-keyed, never one line per issue, because `released`
    // reads `^<id> <rule>` and a per-id line would refuse every In Review row in a
    // relations-free sweep.
    let no_edge_key: Vec<String> = board
        .rows
        .iter()
        .filter(|row| {
            row.payload
                .get("relations")
                .and_then(serde_json::Value::as_object)
                .is_none_or(|relations| !relations.contains_key("blockedBy"))
        })
        .map(|row| row.id.clone())
        .collect();
    if !no_edge_key.is_empty() {
        out.unjudged(
            "graph",
            &format!("unjudgeable-blockedby ({})", sorted(no_edge_key).join(" ")),
        );
    }

    let edges = edges(payloads);

    // `dangling-blocker` IS AN UNJUDGED ARM, NOT A VIOLATION (CLOUD-678): the
    // tracker keeps `blockedBy` after the blocker completes, so an active-only
    // closure carries such an edge for every landed blocker.
    let outside: BTreeSet<&str> = edges
        .iter()
        .filter(|(_, to)| !board.contains(to))
        .map(|(_, to)| to.as_str())
        .collect();
    if !outside.is_empty() {
        let outside = sorted(outside.into_iter().map(ToOwned::to_owned).collect());
        out.unjudged(
            "graph",
            &format!("dangling-blocker ({})", outside.join(" ")),
        );
    }

    let cycle = cycle_members(&edges);
    if !cycle.is_empty() {
        out.violation("graph", &format!("blockedby-cycle ({})", cycle.join(" ")));
    }

    edges
}

/// Which ready-queue rows are schedulable, each exclusion attributed.
fn frontier(
    board: &Board<'_>,
    words: &Vocabulary<'_>,
    edges: &[(String, String)],
    out: &mut Outcome,
) {
    // --- the frontier ------------------------------------------------------------
    //
    // A ready-queue row is on the frontier iff its own payload passes the one
    // Ready grammar and every blocker in the set is resolved. EVERY EXCLUSION IS
    // ATTRIBUTED (CLOUD-251), and the three arms end in three different channels
    // (CLOUD-375): an unready block is the ready queue lying, a payload the grammar
    // could not read is could-not-look, an unlanded blocker is scheduling.
    for row in &board.rows {
        if row.status != words.ready {
            continue;
        }
        let Ok(payload) = Payload::parse(row.payload) else {
            out.unjudged(&row.id, "excluded (unjudgeable-ready-block)");
            continue;
        };
        let Ok(report) = crate::ready::lint(words.grammar, &payload, words.root) else {
            out.unjudged(&row.id, "excluded (unjudgeable-ready-block)");
            continue;
        };
        if !report.findings.is_empty() {
            out.violation(&row.id, "todo-not-ready");
            // The grammar's own rule ids, FORWARDED rather than re-derived: the
            // one definition of Ready keeps its own vocabulary.
            for finding in &report.findings {
                out.forward(format!("{}:{} {}", payload.id, finding.line, finding.rule));
            }
            if report.unjudgeable > 0 {
                out.forward(format!(
                    "{}:{} unjudgeable-relations",
                    payload.id, report.unjudged_line
                ));
            }
            continue;
        }
        if report.unjudgeable > 0 {
            out.unjudged(&row.id, "excluded (unjudgeable-ready-block)");
            continue;
        }
        // THREE ARMS, NOT TWO (CLOUD-678): a blocker outside the set is a question
        // nobody asked, never an unlanded one.
        let mut ok = true;
        let mut blocking = String::new();
        let mut unknown = String::new();
        let mut retired = String::new();
        for (from, to) in edges {
            if *from != row.id {
                continue;
            }
            if !board.contains(to) {
                ok = false;
                unknown.push(' ');
                unknown.push_str(to);
                continue;
            }
            if !blocker_resolved(board, words, to) {
                ok = false;
                blocking.push(' ');
                blocking.push_str(to);
                continue;
            }
            // RETIRED rather than completed: collected, never swallowed.
            if board
                .get(to)
                .is_some_and(|b| b.status_type == "canceled" || b.status_type == "duplicate")
            {
                retired.push(' ');
                retired.push_str(to);
            }
        }
        if ok {
            out.frontier.push(row.id.clone());
            // CLOUD-477's second decision: schedulable, AND the reason on record,
            // since a retired blocker may have taken the premise with it.
            if !retired.is_empty() {
                out.note(&row.id, &format!("frontier-over-retired-blocker{retired}"));
            }
        } else if !unknown.is_empty() {
            out.unjudged(
                &row.id,
                &format!("excluded (unjudgeable-blocker{unknown}{blocking})"),
            );
        } else {
            out.note(&row.id, &format!("excluded (blocked-by{blocking})"));
        }
    }
}

/// Every `(dependent, blocker)` edge, ordered by the dependent's key then the
/// line — the order the program this replaces walked them in.
fn edges(payloads: &[serde_json::Value]) -> Vec<(String, String)> {
    let mut edges: Vec<(String, String)> = Vec::new();
    for payload in payloads {
        let from = payload.get("id").map(text).unwrap_or_default();
        let Some(blockers) = payload
            .get("relations")
            .and_then(|relations| relations.get("blockedBy"))
            .and_then(serde_json::Value::as_array)
        else {
            continue;
        };
        for blocker in blockers {
            if let Some(to) = blocker.get("id").and_then(serde_json::Value::as_str) {
                edges.push((from.clone(), to.to_owned()));
            }
        }
    }
    edges.sort_by(|a, b| {
        by_number(&a.0, &b.0)
            .then_with(|| format!("{} {}", a.0, a.1).cmp(&format!("{} {}", b.0, b.1)))
    });
    edges
}

/// The keys on some `blockedBy` cycle, in key order.
///
/// A self-edge is not a cycle, which is `tsort`'s reading of a pair naming one
/// node twice. Every node whose strongly connected component holds more than
/// one node is reported.
fn cycle_members(edges: &[(String, String)]) -> Vec<String> {
    let mut graph: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    for (from, to) in edges {
        if from != to {
            graph.entry(from.as_str()).or_default().insert(to.as_str());
        }
        graph.entry(to.as_str()).or_default();
    }
    // A node is on a cycle iff it can reach itself.
    let reaches = |start: &str| -> bool {
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut stack: Vec<&str> = graph
            .get(start)
            .map(|next| next.iter().copied().collect())
            .unwrap_or_default();
        while let Some(node) = stack.pop() {
            if node == start {
                return true;
            }
            if seen.insert(node)
                && let Some(next) = graph.get(node)
            {
                stack.extend(next.iter().copied());
            }
        }
        false
    };
    let members: Vec<String> = graph
        .keys()
        .filter(|node| reaches(node))
        .map(|node| (*node).to_owned())
        .collect();
    sorted(members)
}

/// The status-claim scan (CLOUD-234, CLOUD-838): prose is not a second authority
/// for a column.
///
/// CLAIMS, NOT MENTIONS: mention markup is stripped, backticked and quoted spans
/// are neutralised (naming a claim is not making one), and between the key and
/// the column only punctuation, emphasis and whitespace may stand — optionally
/// one present-tense connective. The filler class excludes a newline, so a
/// claim never bridges two lines.
///
/// THE VOCABULARY IS THE SET'S OCCUPIED COLUMNS, never a second copy of the
/// board's list. A claim naming a column nothing in the set occupies is
/// refused as unscannable when it carries a connective (CLOUD-838), because the
/// connective is the only thing that tells an assertion from a capitalised
/// mention once there is no vocabulary to lean on.
fn status_claims(
    board: &Board<'_>,
    words: &Vocabulary<'_>,
    payloads: &[serde_json::Value],
    out: &mut Outcome,
) {
    unjudgeable_descriptions(board, out);
    let Some(Scan {
        claim,
        unspellable,
        key_re,
        column_re,
        whole_column,
        code_span,
        quoted,
    }) = Scan::new(words, payloads)
    else {
        return;
    };

    for row in &board.rows {
        let Some(description) = row
            .payload
            .get("description")
            .and_then(serde_json::Value::as_str)
        else {
            continue;
        };
        let prose = words.grammar.strip_mentions(description);
        let prose = code_span.replace_all(&prose, "CODESPAN");
        let prose = quoted.replace_all(&prose, "QUOTED");

        for found in claim.find_iter(&prose) {
            let span = found.as_str();
            let Some(cited) = key_re.find_iter(span).last().map(|m| m.as_str()) else {
                continue;
            };
            let Some(claimed) = column_re.find_iter(span).last().map(|m| m.as_str()) else {
                continue;
            };
            match board.get(cited) {
                None => out.unjudged(
                    "graph",
                    &format!(
                        "status-claim-unjudgeable ({} claims {cited}, not in the piped set)",
                        row.id
                    ),
                ),
                Some(actual) if actual.status != claimed => out.violation(
                    &row.id,
                    &format!(
                        "status-claim-disagrees ({cited} claimed {claimed}, board says {})",
                        actual.status
                    ),
                ),
                Some(_) => {}
            }
        }

        // THE ALPHABET'S OWN ANTI-VACUITY ARM (CLOUD-838).
        for captures in unspellable.captures_iter(&prose) {
            let Some(token) = captures.get(1).map(|m| m.as_str()) else {
                continue;
            };
            // In the alphabet: the scan above already judged it, and reporting it
            // twice would price one claim under two rule ids.
            if whole_column.is_match(token) {
                continue;
            }
            let Some(cited) = captures
                .get(0)
                .and_then(|span| key_re.find_iter(span.as_str()).last())
                .map(|m| m.as_str().to_owned())
            else {
                continue;
            };
            out.unjudged("graph", &format!("status-claim-unscannable ({} claims {cited} is {token}, which no piped issue occupies — pipe one that does)", row.id));
        }
    }
}

/// ANTI-VACUITY for the claim scan: a set whose descriptions were projected away
/// has nothing to scan, and "found no claims" would read as "made no false
/// claims".
fn unjudgeable_descriptions(board: &Board<'_>, out: &mut Outcome) {
    let no_description: Vec<String> = board
        .rows
        .iter()
        .filter(|row| {
            !row.payload
                .get("description")
                .is_some_and(serde_json::Value::is_string)
        })
        .map(|row| row.id.clone())
        .collect();
    if !no_description.is_empty() {
        out.unjudged(
            "graph",
            &format!(
                "unjudgeable-description ({})",
                sorted(no_description).join(" ")
            ),
        );
    }
}

/// The patterns one status-claim scan runs, composed once per set.
struct Scan {
    claim: Regex,
    unspellable: Regex,
    key_re: Regex,
    column_re: Regex,
    whole_column: Regex,
    code_span: Regex,
    quoted: Regex,
}

impl Scan {
    /// Compose the scan over the set's occupied columns, or `None` when a
    /// pattern will not compile — nothing is then scanned, as before the split.
    fn new(words: &Vocabulary<'_>, payloads: &[serde_json::Value]) -> Option<Self> {
        let mut columns: Vec<String> = payloads
            .iter()
            .filter_map(|row| row.get("status").map(text))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        // LONGEST FIRST, so a leftmost-first engine picks what a leftmost-longest
        // one would: a column that is a prefix of another never wins over it.
        columns.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        let alphabet = columns
            .iter()
            .map(|column| regex::escape(column))
            .collect::<Vec<_>>()
            .join("|");
        let key = words.grammar.key_pattern();
        let connective = words.connective.as_str();
        let filler = r"[^[:alnum:]\\\n]*";
        let capspan = r"[A-Z][A-Za-z]*(?:[ \t\r]+[A-Z][A-Za-z]*)*";
        Some(Self {
            claim: Regex::new(&format!(
                "(?:{key}){filler}(?:(?:{connective}){filler})?(?:{alphabet})"
            ))
            .ok()?,
            unspellable: Regex::new(&format!(
                "(?:{key}){filler}(?:{connective}){filler}({capspan})"
            ))
            .ok()?,
            key_re: Regex::new(key).ok()?,
            column_re: Regex::new(&format!("(?:{alphabet})")).ok()?,
            whole_column: Regex::new(&format!("^(?:{alphabet})$")).ok()?,
            code_span: Regex::new("`[^`]*`").ok()?,
            quoted: Regex::new("\"[^\"]*\"").ok()?,
        })
    }
}

/// Mint one `board-move.<KEY>` receipt per judged id (CLOUD-512).
///
/// Called ONLY on the coherent path: a board carrying a violation must not
/// authorise a move. One file per id, because a bare "the gate ran" receipt is
/// satisfied by judging one clean issue and then sweeping fifteen. TRUNCATED,
/// not appended, so the engine's mtime bound reads the freshest adjudication.
///
/// The id is held to the consumer's key grammar before it becomes a path
/// component, so a value that is not a key mints nothing. FAIL-SOFT: a store
/// that cannot be written changes no verdict — this gate's verdict is about the
/// board, never about the store.
pub fn mint(receipts: &Path, grammar: &Grammar, ids: &[String], stamp: u64) {
    if std::fs::create_dir_all(receipts).is_err() {
        return;
    }
    for id in ids {
        if grammar.key_of(id).is_none() {
            continue;
        }
        let _ = crate::durable::replace(
            receipts.join(format!("board-move.{id}")),
            format!("{stamp} {id}\n"),
        );
    }
}
