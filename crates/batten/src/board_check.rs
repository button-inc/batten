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
//! # This module READS; the `tracker-hygiene` preset DECIDES
//!
//! The migration's rule puts a generic decision in a preset bundle and only the
//! mechanism in the engine, and this module is held to it. What is here is
//! acquisition and extraction: parsing the payload set, normalising a row's
//! column onto the consumer's `[board]` words, asking the one definition of
//! Ready about a row, running the declared `[[pattern]]` expressions over a
//! body, and reading the tracked tree and its history. Each question's answer
//! is a READING — one tab-separated line per fact, the record shape the preset
//! already reads — and every verdict over it is a module in
//! `crates/batten/src/policy/presets/tracker-hygiene/`, evaluated in process:
//! which column claim is false, whether the relation is cyclic, which blocker
//! holds a row off the frontier, whether a marked path was deleted, whether a
//! cited clause is carried. `policy/duplicate-close.rego` was the precedent
//! that refuted the earlier revision's claim that no module could read a
//! payload set.
//!
//! A reading field names a fact and never judges it: `settles` says the row's
//! status TYPE is one the consumer declared settling, and the preset decides
//! that the review column settles too; `found` says a corpus file carries a
//! token, and the preset decides that its absence is a refusal.
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
//! `crate::board` exists to refuse. The preset reads only the reading, whose
//! column field is already normalised onto `ready`, `in-progress`, `review` and
//! `other`, so no module names a consumer's column either.
//!
//! # Three channels, and they never collapse
//!
//! A line on stderr is `<id> <rule>` — a report (the board is lying, exit `2`),
//! an unjudged gap (the caller did not pipe enough to judge, exit `3`), or a note
//! (an honest frontier exclusion, exit unmoved). The first two are the preset's
//! `violation`s, told apart by their declared class; a note is its `board_notes`
//! set and the frontier its `board_frontier` set, because neither is a refusal
//! and the registry holds refusals. A gap outranks a report in the graph,
//! because a verdict over a set only partly read is not a verdict: the caller's
//! next action is a re-fetch, after which more violations may appear. Both
//! report sets print before the exit either way, so one never hides the other.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! An id, a rule, a column word, a path and line, a count — never a byte of an
//! issue body and never a line of a source file. Bodies carry customer detail,
//! and the reading carries none of them either: a claim is its key and column,
//! a citation its token or path.

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use regex::Regex;
use serde_json::Value;

use crate::Result;
use crate::board::Board;
use crate::error::UsageError;
use crate::exit::ExitCode;
use crate::facts::Look;
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

/// The preset whose modules decide every question below.
const PRESET: &str = "tracker-hygiene";

/// The record family each question's reading is handed to the preset under.
/// One per question, so a module deciding one never reads another's facts.
const GRAPH: &str = "board-graph";
/// See [`GRAPH`].
const CITES: &str = "board-cites";
/// See [`GRAPH`].
const REFS: &str = "board-refs";

/// The preset's set of non-refusal lines: frontier exclusions, forwarded Ready
/// pointers and prospective citations.
const NOTES: &str = "board_notes";
/// The preset's set of ready-frontier ids.
const FRONTIER: &str = "board_frontier";

/// The graph's report lane: the board is signalling falsely.
const GRAPH_REPORT: &str = "issue state wrong";
/// The graph's gap lane: the piped set cannot answer.
const GRAPH_GAP: &str = "issue judge partial";
/// `--cites`'s refusal: a citation the tree does not carry.
const CITE_REFUSED: &str = "path point missing";
/// `--refs`'s refusal: a clause citation its issue does not carry.
const REF_REFUSED: &str = "source point wrong";
/// `--refs`'s gap: a cited issue the set did not carry.
const REF_GAP: &str = "source point unread";

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
        match cites
            .read(&set, declared)
            .and_then(|reading| decide(CITES, &reading.lines).map(|decided| (reading, decided)))
        {
            Ok((reading, decided)) => match render_cites(&reading, &decided, out, err)? {
                Some(proven) => refused |= proven,
                None => unjudged = true,
            },
            Err(why) => {
                writeln!(err, "::error:: board check --cites: {why}")?;
                unjudged = true;
            }
        }
    }
    if ask.refs {
        let refs = Refs::resolve(declared)?;
        match refs
            .read(&set, declared)
            .and_then(|reading| decide(REFS, &reading.lines).map(|decided| (reading, decided)))
        {
            Ok((reading, decided)) => match render_refs(&reading, &decided, out, err)? {
                Some((proven, gaps)) => {
                    refused |= proven;
                    unjudged |= gaps;
                }
                None => unjudged = true,
            },
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

/// One reading field. A tab or a line break inside a value would shift every
/// column after it, so each becomes a space: the report still names the value,
/// and the line still has the arity its kind declares.
fn field(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

/// A boolean fact as the reading spells it.
const fn yes(flag: bool) -> &'static str {
    if flag { "yes" } else { "no" }
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

// --- the preset, asked in process ----------------------------------------------

/// What the preset decided over one reading.
#[derive(Debug, Default)]
pub struct Decided {
    /// Each `violation`: its declared class, and its subjects rendered as the
    /// pointer line a reader greps (`<id> <rule>`).
    pub findings: Vec<(String, String)>,
    /// The non-refusal lines, `board_notes`.
    pub notes: Vec<String>,
    /// The ready frontier, `board_frontier`, in byte-stable order.
    pub frontier: Vec<String>,
}

impl Decided {
    /// Every finding of one class, as pointer lines, in byte-stable order.
    fn lines_of(&self, verdict: &str) -> Vec<String> {
        let mut lines: Vec<String> = self
            .findings
            .iter()
            .filter(|(class, _)| class == verdict)
            .map(|(_, line)| line.clone())
            .collect();
        sort_lines(&mut lines);
        lines
    }

    /// A class this verb does not render — a module speaking a dialect the
    /// verb has no lane for, which is could-not-look rather than a silent drop.
    fn unknown(&self, known: &[&str]) -> Option<&str> {
        self.findings
            .iter()
            .map(|(class, _)| class.as_str())
            .find(|class| !known.contains(class))
    }
}

/// Order pointer lines by their leading id, [`by_num`], then whole.
fn sort_lines(lines: &mut [String]) {
    lines.sort_by(|left, right| {
        let key = |line: &str| line.split(' ').next().unwrap_or_default().to_owned();
        let (left_key, right_key) = (key(left), key(right));
        by_num(&left_key)
            .cmp(&by_num(&right_key))
            .then_with(|| left.cmp(right))
    });
}

/// Hand one reading to the preset and read back what it decided.
///
/// The preset is compiled from this build's own manifest, so the decision a
/// consumer gets is the one the binary ships — the same bytes a `[[rule]]` row
/// enabling `tracker-hygiene` would load. The reading is the tree document's
/// `records` shape, keyed by `family`, which is what every module in the bundle
/// reads; a module deciding another family's record reads nothing here.
///
/// `Err` is could-not-look: the preset is missing from the build, will not
/// compile, or faulted over the reading.
fn decide(family: &str, lines: &[String]) -> std::result::Result<Decided, String> {
    let manifest = crate::preset::MANIFESTS
        .iter()
        .find(|manifest| manifest.name == PRESET)
        .ok_or_else(|| format!("this build ships no `{PRESET}` preset to decide with"))?;
    let sources = manifest.modules_at(crate::rules::RuleScope::Tree);
    let bundle = crate::policy::compile(PRESET, &sources, &Value::Object(serde_json::Map::new()))
        .map_err(|_| format!("the `{PRESET}` preset does not compile"))?;
    let mut records = serde_json::Map::new();
    records.insert(family.to_owned(), Value::from(lines.to_vec()));
    let mut tree = serde_json::Map::new();
    tree.insert("records".to_owned(), Value::Object(records));
    let mut document = serde_json::Map::new();
    document.insert("tree".to_owned(), Value::Object(tree));
    let input = Value::Object(document).to_string();
    let faulted = || format!("the `{PRESET}` preset could not decide over the {family} reading");
    let violations = match crate::policy::deny(&bundle, &input) {
        Look::Is(found) => found,
        Look::IsNot | Look::CouldNotLook => return Err(faulted()),
    };
    let strings = |rule: &str| match crate::policy::strings(&bundle, &input, rule) {
        Look::Is(found) => Ok(found),
        Look::IsNot | Look::CouldNotLook => Err(faulted()),
    };
    let mut frontier = strings(FRONTIER)?;
    sort_ids(&mut frontier);
    let mut notes = strings(NOTES)?;
    sort_lines(&mut notes);
    Ok(Decided {
        findings: violations
            .iter()
            .map(|violation| {
                (
                    violation.verdict.clone(),
                    crate::verdict::render_subjects(&violation.subjects),
                )
            })
            .collect(),
        notes,
        frontier,
    })
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
    /// Resolve every word the graph's reading normalises with.
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

    /// A status, normalised onto the four words the preset decides with. The
    /// consumer's column names stop here: the preset never reads one.
    fn column(&self, status: &str) -> &'static str {
        if status == self.ready {
            "ready"
        } else if status == self.in_progress {
            "in-progress"
        } else if status == self.review {
            "review"
        } else {
            "other"
        }
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

impl Presence {
    /// The reading's token.
    const fn token(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Empty => "empty",
            Self::Set => "set",
        }
    }
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

    /// Whether this row's status TYPE is one of `types`.
    fn typed(&self, types: &[String]) -> bool {
        self.status_type
            .as_deref()
            .is_some_and(|kind| types.iter().any(|declared| declared == kind))
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

impl Readiness {
    /// The reading's token.
    const fn token(&self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::Unready(_) => "unready",
            Self::Unjudgeable => "unjudgeable",
        }
    }
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

/// The graph's reading, and the two counts the verb prints itself.
#[derive(Debug, Default)]
pub struct Reading {
    /// One tab-separated fact per line, the record the preset reads.
    pub lines: Vec<String>,
    /// Every row read, in byte-stable order — the ids a coherent board mints
    /// a receipt for.
    pub ids: Vec<String>,
    /// How many rows sit in the pulled column: a measurement, not a verdict.
    pub wip: usize,
}

// THE DECLARED MUTATIONS, beside the extraction they unmake. Every VERDICT's
// mutations moved with it into the preset's modules; what stays here is the
// reading, and a mutation of the reading is caught by the same compiled tier —
// a fact the preset never sees is a verdict it never reaches. One suite serves
// every row in this file, because `batten mutate` reads the FIRST `MUTANT-SUITE`
// line of a source. No pattern or case here carries a `|`: the row is split on
// it.
//MUTANT-SUITE crates/batten/tests/it/board_check.rs
//MUTANT blocker-edges-unread|s@^            lines.push(format!("edge\\t{}\\t{}\\t{}", from, field(to), by_num(to).0));$@            let _ = to;@|a_blocked_by_cycle_is_reported_with_its_members
//MUTANT claim-scan-unread|s@^                        "claim\\t{}\\t{}\\t{}",$@                        "unread\\t{}\\t{}\\t{}",@|a_body_claiming_a_column_the_board_contradicts_is_reported
//MUTANT readiness-unread|s@^        if \["ready", "review"\].contains(.column) {$@        if false {@|a_todo_issue_with_no_ready_block_is_refused

/// Read the graph over a payload set.
///
/// `None` is an input refusal: an empty set, or a payload carrying no `id` or no
/// `status`.
///
/// ONE ROW PER ID, THE FIRST: the preset indexes rows by id, and two payloads
/// for one key are one row fetched twice — the index this replaced already
/// answered every lookup from the first.
///
/// The lines, one kind per first field, each of fixed arity:
///
/// ```text
/// row       <ordinal> <id> <status> <column> <assigned> <prs> <milestone> <parent|-> <edges> <settles> <retires> <described>
/// edge      <from> <to> <the target's ordinal>
/// ready     <id> <ready|unready|unjudgeable> <the §6 bump|->
/// forward   <id> <the Ready gate's own pointer line>
/// claim     <row> <cited> <column>
/// asserted  <row> <cited> <span>
/// scan      broken
/// ```
#[must_use]
pub fn read_graph(
    set: &[Value],
    grammar: &Grammar,
    vocabulary: &Vocabulary,
    root: &Path,
) -> Option<Reading> {
    if set.is_empty() {
        return None;
    }
    let mut rows = Vec::with_capacity(set.len());
    for value in set {
        rows.push(Row::read(value)?);
    }
    rows.sort_by(|left, right| by_num(&left.id).cmp(&by_num(&right.id)));
    let mut seen = BTreeSet::new();
    rows.retain(|row| seen.insert(row.id.clone()));
    let mut lines = Vec::new();
    for row in &rows {
        let column = vocabulary.column(&row.status);
        lines.push(format!(
            "row\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            by_num(&row.id).0,
            field(&row.id),
            field(&row.status),
            column,
            yes(row.assigned),
            row.prs,
            row.milestone.token(),
            row.parent.as_deref().map_or_else(|| "-".to_owned(), field),
            if row.edges_declared {
                "declared"
            } else {
                "absent"
            },
            yes(row.typed(&vocabulary.settled_types)),
            yes(row.typed(&vocabulary.retired_types)),
            yes(row.description.is_some()),
        ));
        let from = field(&row.id);
        for to in &row.blocked_by {
            lines.push(format!("edge\t{}\t{}\t{}", from, field(to), by_num(to).0));
        }
        if ["ready", "review"].contains(&column) {
            let (verdict, bump) = readiness(grammar, row.value, root);
            lines.push(format!(
                "ready\t{from}\t{}\t{}",
                verdict.token(),
                bump.as_deref().map_or_else(|| "-".to_owned(), field)
            ));
            if let Readiness::Unready(forwarded) = &verdict {
                for line in forwarded {
                    lines.push(format!("forward\t{from}\t{}", field(line)));
                }
            }
        }
    }
    read_claims(&rows, grammar, vocabulary, &mut lines);
    Some(Reading {
        lines,
        ids: rows.iter().map(|row| row.id.clone()).collect(),
        wip: rows
            .iter()
            .filter(|row| row.status == vocabulary.in_progress)
            .count(),
    })
}

/// Status claims, extracted: every id-first span the declared connective allows
/// between a key and a column word (CLOUD-234, CLOUD-838).
///
/// THE VOCABULARY IS THE PIPED SET'S OCCUPIED STATUSES, never a second copy of
/// the board's list. A claim is an id-first span whose connective is
/// allowlisted — only punctuation, emphasis and whitespace, optionally one
/// declared present-tense connective, may stand between the key and the column
/// word — because no blocklist of narration verbs ends. Case-sensitive, since
/// the columns are proper nouns the payload spells exactly.
///
/// Two kinds come out: a `claim` naming a column the set occupies, and an
/// `asserted` capitalised span behind a REQUIRED connective, whatever it names.
/// Whether the first disagrees with the board, and whether the second names a
/// column nobody occupies, is the preset's to decide. A scan whose expressions
/// will not compose extracted nothing, which is not the same as finding nothing,
/// so it says `scan broken`.
fn read_claims(
    rows: &[Row<'_>],
    grammar: &Grammar,
    vocabulary: &Vocabulary,
    lines: &mut Vec<String>,
) {
    let Some(scan) = Scan::build(rows, grammar, &vocabulary.connective) else {
        lines.push("scan\tbroken".to_owned());
        return;
    };
    for row in rows {
        let Some(description) = row.description else {
            continue;
        };
        let prose = scan.neutralised(grammar, description);
        for line in prose.lines() {
            for found in scan.claim.captures_iter(line) {
                let cited = found.name("key").map_or("", |m| m.as_str());
                let claimed = found.name("column").map_or("", |m| m.as_str());
                if !cited.is_empty() {
                    lines.push(format!(
                        "claim\t{}\t{}\t{}",
                        field(&row.id),
                        field(cited),
                        field(claimed)
                    ));
                }
            }
            for found in scan.asserted.captures_iter(line) {
                let cited = found.name("key").map_or("", |m| m.as_str());
                let span = found.name("span").map_or("", |m| m.as_str());
                if !cited.is_empty() && !span.is_empty() {
                    lines.push(format!(
                        "asserted\t{}\t{}\t{}",
                        field(&row.id),
                        field(cited),
                        field(span)
                    ));
                }
            }
        }
    }
}

/// The compiled expressions of one claim scan.
#[derive(Debug)]
struct Scan {
    claim: Regex,
    asserted: Regex,
    code_span: Regex,
    quoted: Regex,
}

impl Scan {
    /// `None` only when an expression composed from the declared rows will not
    /// compile — the reading says so, and the preset reports it as a gap.
    fn build(rows: &[Row<'_>], grammar: &Grammar, connective: &str) -> Option<Self> {
        let mut columns: Vec<String> = rows
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
        let key = grammar.key_expression();
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
}

/// Render the graph's decision, and mint the move receipts on a coherent board.
fn graph(
    set: &[Value],
    declared: &Declared<'_>,
    now: u64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let vocabulary = Vocabulary::resolve(declared.board, declared.patterns)?;
    let Some(reading) = read_graph(set, declared.grammar, &vocabulary, declared.root) else {
        writeln!(
            err,
            "::error:: board check: stdin is not a set of get_issue payloads (need id and status per issue)"
        )?;
        return Ok(ExitCode::Internal);
    };
    let decided = match decide(GRAPH, &reading.lines) {
        Ok(decided) => decided,
        Err(why) => {
            writeln!(err, "::error:: board check: {why}")?;
            return Ok(ExitCode::Internal);
        }
    };
    if let Some(class) = decided.unknown(&[GRAPH_REPORT, GRAPH_GAP]) {
        writeln!(
            err,
            "::error:: board check: the preset raised `{class}`, which the graph has no lane for"
        )?;
        return Ok(ExitCode::Internal);
    }
    let reports = decided.lines_of(GRAPH_REPORT);
    let gaps = decided.lines_of(GRAPH_GAP);
    let mut lines: Vec<String> = reports
        .iter()
        .chain(&gaps)
        .chain(&decided.notes)
        .cloned()
        .collect();
    sort_lines(&mut lines);
    for line in &lines {
        writeln!(err, "{line}")?;
    }
    writeln!(out, "wip {}", reading.wip)?;
    for id in &decided.frontier {
        writeln!(out, "frontier {id}")?;
    }
    if !reports.is_empty() {
        writeln!(
            err,
            "::error:: board check: {} violation(s) — the board is signalling falsely",
            reports.len()
        )?;
    }
    // COULD-NOT-LOOK OUTRANKS A VIOLATION HERE (CLOUD-251): a verdict over a set
    // this could only partly read is not a verdict.
    if !gaps.is_empty() {
        writeln!(
            err,
            "::error:: board check: {} payload(s) could not be judged — re-fetch with the \
             relations, attachments, milestones and descriptions included",
            gaps.len()
        )?;
        return Ok(ExitCode::Internal);
    }
    if !reports.is_empty() {
        return Ok(ExitCode::Violation);
    }
    mint_receipts(declared, &reading.ids, now);
    writeln!(
        out,
        "board check: board coherent ({} issues)",
        reading.ids.len()
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

/// The citation reading, and the one clone property the verb prints itself.
#[derive(Debug, Default)]
struct CiteReading {
    lines: Vec<String>,
    cited: usize,
    history: bool,
}

//MUTANT fixtures-satisfy-a-citation|s@^        let drop = &self.exclude;$@        let drop: \&[crate::rules::Selector] = \&[];@|a_citation_that_resolves_only_in_a_fixture_and_nowhere_else_is_refused
//MUTANT superseded-block-is-judged|s@^            start = Some(at);$@            start = start.or(Some(at));@|the_last_opener_is_the_live_block_and_an_earlier_one_is_history
//MUTANT marker-never-read|s@^                Some(marker) => text.contains(.format!("`{path}` {marker}")),$@                Some(_) => false,@|a_citation_the_block_marks_new_is_prospective_not_fatal

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

    /// Read every payload's LIVE Ready block against the tree.
    ///
    /// ```text
    /// test  <key> <token> <found>
    /// path  <key> <path> <exists> <marked> <deleted: yes|no|unknown>
    /// ```
    ///
    /// `Err` is could-not-look: a set that is not payloads carrying a body, or a
    /// tree that cannot be enumerated or holds nothing to resolve against.
    fn read(
        &self,
        set: &[Value],
        declared: &Declared<'_>,
    ) -> std::result::Result<CiteReading, String> {
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
        let history = !crate::git::is_shallow(declared.root).unwrap_or(true);
        let mut lines = BTreeSet::new();
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
                &mut lines,
            );
            self.paths_in(&key, &block, declared.root, history, &mut lines);
        }
        Ok(CiteReading {
            cited: lines.len(),
            lines: lines.into_iter().collect(),
            history,
        })
    }

    /// Cited test names, inside the obligations clause only — a greedier span
    /// would read an unrelated backticked symbol in a later clause as an
    /// obligation — and whether any corpus file carries each.
    fn tests_in(
        &self,
        key: &str,
        block: &[&str],
        clause: &Regex,
        contents: &[String],
        lines: &mut BTreeSet<String>,
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
            let found = contents.iter().any(|text| text.contains(token));
            lines.insert(format!(
                "test\t{}\t{}\t{}",
                field(key),
                field(token),
                yes(found)
            ));
        }
    }

    /// Cited paths, anywhere in the live block: whether each exists, whether the
    /// block marks it prospective, and — for a marked one on a full clone —
    /// whether an ancestor deleted it (CLOUD-920).
    ///
    /// The marker is read WITH its path, so one marker elsewhere in the block
    /// cannot excuse every citation in it. History is asked only about a marked
    /// absent path, and a shallow clone answers `unknown`, never `no`.
    fn paths_in(
        &self,
        key: &str,
        block: &[&str],
        root: &Path,
        history: bool,
        lines: &mut BTreeSet<String>,
    ) {
        let text = block.join("\n");
        let paths: BTreeSet<&str> = self
            .cited_path
            .find_iter(&text)
            .map(|found| found.as_str().trim_matches('`'))
            .filter(|path| path.contains('/'))
            .collect();
        for path in paths {
            let exists = root.join(path).exists();
            let marked = match self.prospective.as_deref() {
                Some(marker) => text.contains(&format!("`{path}` {marker}")),
                None => false,
            };
            let deleted = if exists || !marked || !history {
                "unknown"
            } else {
                match crate::git::path_was_deleted(root, path) {
                    Ok(Some(true)) => "yes",
                    Ok(Some(false)) => "no",
                    Ok(None) | Err(_) => "unknown",
                }
            };
            lines.insert(format!(
                "path\t{}\t{}\t{}\t{}\t{deleted}",
                field(key),
                field(path),
                yes(exists),
                yes(marked)
            ));
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

/// Render `--cites`, and say whether a citation was refused — `None` when the
/// preset raised a class this direction has no lane for.
///
/// Notes print before the verdict and on stderr either way: a prospective
/// citation is information about a correct block and must neither move the
/// exit code nor be buried under a refusal after it.
fn render_cites(
    reading: &CiteReading,
    decided: &Decided,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Option<bool>> {
    if let Some(class) = decided.unknown(&[CITE_REFUSED]) {
        writeln!(
            err,
            "::error:: board check --cites: the preset raised `{class}`, which this direction has no lane for"
        )?;
        return Ok(None);
    }
    let findings = decided.lines_of(CITE_REFUSED);
    let prospective = decided.notes.len();
    for note in &decided.notes {
        writeln!(err, "  {note}")?;
    }
    if !decided.notes.is_empty() && !reading.history {
        writeln!(
            err,
            "::notice:: board check --cites: {prospective} prospective citation(s) above, and this clone is \
             SHALLOW — so a prospective marker could not be checked against history. A marker on \
             a path that was deleted rather than never written is not detectable here; a full \
             clone can check it."
        )?;
    }
    if !findings.is_empty() {
        writeln!(
            err,
            "::error:: board check --cites: a Ready block cites something the tree does not \
             carry. This checks EXISTENCE, never relevance — whether a test that exists is the \
             right test is not computable (CLOUD-93). A citation resolving only in an excluded \
             path is refused, because a fixture quoting the citation is not the thing cited:"
        )?;
        for finding in &findings {
            writeln!(err, "  {finding}")?;
        }
        writeln!(
            err,
            "::error:: board check --cites: {} of {} citation(s) resolve nothing",
            findings.len(),
            reading.cited
        )?;
        return Ok(Some(true));
    }
    let resolved = reading.cited.saturating_sub(findings.len() + prospective);
    if prospective > 0 {
        writeln!(
            out,
            "board check --cites: {resolved} of {} citation(s) resolve against the tree; {prospective} prospective",
            reading.cited
        )?;
    } else {
        writeln!(
            out,
            "board check --cites: {resolved} of {} citation(s) resolve against the tree",
            reading.cited
        )?;
    }
    Ok(Some(false))
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

/// The clause-citation reading, and how many citations it holds.
#[derive(Debug, Default)]
struct RefReading {
    lines: Vec<String>,
    hits: usize,
}

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

    /// Read every clause citation in the tree, and what the piped bodies carry.
    ///
    /// ```text
    /// hit     <path> <line> <key> <clause>
    /// issue   <key>                 — a cited key whose body the set carries
    /// clause  <key> <clause>        — a clause that body DECLARES
    /// ```
    ///
    /// Only the cited keys' bodies are read, and only for their clause labels:
    /// the reading carries a key and a number, never a line of a body.
    fn read(
        &self,
        set: &[Value],
        declared: &Declared<'_>,
    ) -> std::result::Result<RefReading, String> {
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
        let hits = self.hits(declared.root)?;
        let mut lines = Vec::with_capacity(hits.len());
        let mut cited: BTreeSet<&str> = BTreeSet::new();
        for (path, line, key, clause) in &hits {
            lines.push(format!(
                "hit\t{}\t{line}\t{}\t{}",
                field(path),
                field(key),
                field(clause)
            ));
            cited.insert(key.as_str());
        }
        for key in cited {
            let body = set
                .iter()
                .find(|value| value.get("id").map(scalar).as_deref() == Some(key))
                .and_then(|value| value.get("description"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if body.is_empty() {
                continue;
            }
            lines.push(format!("issue\t{}", field(key)));
            let body_lines: Vec<&str> = body.lines().collect();
            for clause in declared_clauses(&body_lines, grammar, &self.tag) {
                lines.push(format!("clause\t{}\t{}", field(key), field(clause)));
            }
        }
        Ok(RefReading {
            lines,
            hits: hits.len(),
        })
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

/// Render `--refs`, and say (refused, could-not-look) — `None` when the preset
/// raised a class this direction has no lane for.
fn render_refs(
    reading: &RefReading,
    decided: &Decided,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<Option<(bool, bool)>> {
    if let Some(class) = decided.unknown(&[REF_REFUSED, REF_GAP]) {
        writeln!(
            err,
            "::error:: board check --refs: the preset raised `{class}`, which this direction has no lane for"
        )?;
        return Ok(None);
    }
    let gaps = decided.lines_of(REF_GAP);
    let findings = decided.lines_of(REF_REFUSED);
    if !gaps.is_empty() {
        writeln!(
            err,
            "::error:: board check --refs: cited issues are absent from the piped payload set, \
             so their citations could not be judged. Fetch them and pipe again — an unfetched \
             issue looks exactly like a clean one (CLOUD-189):"
        )?;
        for gap in &gaps {
            writeln!(err, "  {gap}")?;
        }
    }
    if !findings.is_empty() {
        writeln!(
            err,
            "::error:: board check --refs: citations name a clause their issue does not carry. \
             Cite the clause that holds the content, or the issue's own clause if it moved \
             (CLOUD-809):"
        )?;
        for finding in &findings {
            writeln!(err, "  {finding}")?;
        }
    }
    if gaps.is_empty() && findings.is_empty() {
        writeln!(
            out,
            "board check --refs: every clause citation in the tree resolves ({} checked)",
            reading.hits
        )?;
    }
    Ok(Some((!findings.is_empty(), !gaps.is_empty())))
}

#[cfg(test)]
mod tests {
    use super::{by_num, field, payload_set, sort_lines};

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
    fn pointer_lines_order_by_their_leading_id_numerically() {
        let mut lines = vec![
            "A-10 todo-not-ready".to_owned(),
            "graph dangling-blocker (A-99)".to_owned(),
            "A-9 in-review-no-pr".to_owned(),
        ];
        sort_lines(&mut lines);
        assert_eq!(
            lines,
            [
                "graph dangling-blocker (A-99)",
                "A-9 in-review-no-pr",
                "A-10 todo-not-ready"
            ]
        );
    }

    #[test]
    fn a_field_never_carries_a_separator_into_the_reading() {
        assert_eq!(field("In\tReview\nnow"), "In Review now");
        assert_eq!(field("plain"), "plain");
    }
}
