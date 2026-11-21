//! Record what a tool result said, under a declaration the consumer owns
//! (CLOUD-1051).
//!
//! # Why this exists beside [`crate::mint`] rather than inside it
//!
//! [`crate::mint`] answers *"file a receipt keyed to a subject this result
//! names"*, and its placeholder vocabulary is deliberately closed: six forms over
//! a path, none of which can express a value some OTHER program decided. That
//! bound is correct for a receipt — a receipt attests that a call happened — and
//! it is what makes a mint auditable by reading one template.
//!
//! A recorder answers a different question: *"what did this write DO, judged by
//! the gates this repository already owns"*. The censused instance is a board
//! write whose refinement verdict is another gate's exit status over a payload
//! assembled from two halves of the envelope. No path selector reaches that, and
//! widening `mint`'s vocabulary until it did would give every receipt the ability
//! to spawn — a much larger blast radius than the one row that needs it.
//!
//! # Non-negotiable rule 1 is the whole design constraint
//!
//! **Nothing here names a tracker, a column, a verdict token or a program.** The
//! record's shape is a consumer's `[[recorder]]` row: which tool, which columns in
//! which order, and for each column an expression over the closed vocabulary
//! [`Value`] documents. A reader who wants to know what the columns MEAN reads
//! `batten.toml`; this module only knows how to evaluate an expression and append
//! a line.
//!
//! That is what the alternative could not do. Porting the shell recorder by
//! transcribing its seven columns into Rust would have put `issue`, `comment`,
//! `ready`, `unready` and two program paths inside `crates/batten`, which is
//! exactly the violation a grep for a consumer's names is supposed to return zero
//! hits for.
//!
//! # Every failure is silent, and that is inherited rather than chosen
//!
//! A recorder runs on `PostToolUse`. A recorder that blocked, errored or printed
//! would cause the failure the sink rules exist to catch — pressure toward not
//! writing to the board at all. So every fallible step degrades to [`ABSENT`],
//! and a row that cannot be assembled is simply not written. The gate that reads
//! the record already treats `-` as *could not look* and passes on it, so a
//! degraded column is a quieter answer and never a louder one.
//!
//! # Spawning, declared as an inventory row
//!
//! [`run_program`] is a spawn, and `clippy.toml` makes every spawn an inventory
//! row rather than a refusal. It is bounded three ways: only a program the
//! committed config names, only when the tool selector already matched, and only
//! with the assembled stdin this module built. The tool match is what keeps the
//! per-call budget intact — the overwhelming majority of tool results select no
//! recorder and reach none of this.

use std::collections::BTreeMap;
use std::path::Path;

#[cfg(test)]
use crate::config_check::recorder::validate;
use crate::config_model::{
    Ask, Column, Program, Read, RecordKey, Recorded, RecorderDeclared as Declared, Value,
};

/// The token every unresolvable value renders as.
///
/// Shared with [`crate::mint::ABSENT`]'s reasoning rather than its constant,
/// because the two modules write different records and a reader of either needs
/// the same three-valued read: a column that is `-` is *could not look*, never
/// *looked and found nothing*. Collapsing those is the CLOUD-251 shape every
/// record here is careful to avoid.
pub const ABSENT: &str = "-";

/// What one recorder row made of this call: not its subject, its subject but
/// unanswerable, or a row that applies (CLOUD-1126).
///
/// **The middle arm is the one this type exists for, and it used to be
/// indistinguishable from the first.** `satisfied` returned one bool, so a row
/// whose SELECTOR matched a call that then failed to answer was folded in with
/// every call the row was never about — and a recorder that could not run wrote
/// exactly what a recorder that ran and found nothing wrote, which is nothing.
///
/// Measured on PR #726: `pr-body-closes` selects a `gh pr view` and reads its
/// `stdout`. `gh` is not installed in the web sandbox, so the call exits without
/// stdout, `requires` went unmet, no `pr-closes` record could exist — and
/// `filed-here`'s first exemption, the row a PR closes, was structurally
/// unreachable rather than merely unsatisfied. The body carried
/// `Closes CLOUD-1119` throughout and the refusal fired on every subject anyway.
///
/// That is `.claude/rules/policy-modules.md`'s own rule for tree sources —
/// *"a module that iterates only `documents` reports green over a file it never
/// read"* — arriving on the recorder surface, where CLOUD-1049 shipped it for
/// parse failures and nothing shipped it for this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// This call is not what the row selects for. Silence is the right answer and
    /// carries no information.
    NotSelected,
    /// The row selected this call and the call did not answer it. The payload is
    /// the reason CLASS, never the call's own output (non-negotiable rule 4).
    Blocked(&'static str),
    /// The row applies to this call.
    Applies,
}

/// The reason class for a selected call that produced none of the row's inputs.
///
/// A class rather than the path itself: which path a row requires is its
/// declaration, and a reader wants to know that the recorder could not look
/// rather than to re-read the config through a finding.
pub const BLOCKED_REQUIRED_ABSENT: &str = "required-absent";

/// Whether every required result path resolved, no refusing input path did, and
/// every input path the row matches on carries a value its pattern accepts.
///
/// Takes the whole [`Context`] rather than two values because the third question
/// needs the pattern table, and threading one more parameter through every caller
/// would put the same three things in two orders.
///
/// Kept as the bool every caller already reads; [`outcome`] is what separates its
/// two false arms.
#[must_use]
pub fn satisfied(declared: &Declared, context: &Context<'_>) -> bool {
    matches!(outcome(declared, context), Outcome::Applies)
}

/// [`satisfied`]'s three-valued reading.
///
/// **The order is the predicate.** Selection is decided FIRST — the refusing
/// inputs and the matching patterns — because a call the row was never about must
/// report `NotSelected` rather than `Blocked`, however many of its required paths
/// are missing. Reading it the other way round would file a could-not-look for
/// every unrelated tool call in the session, which is the noise that gets a
/// channel ignored.
///
/// # A ROW WITH NO INPUT SELECTOR IS SELECTED BY EVERY CALL OF ITS TOOL
///
/// Both selector lists are `all` over a possibly-empty collection, so an empty
/// one holds vacuously. That is correct and intended where the tool's identity
/// IS the question — [`Declared::requires_input_matching`] says so, and a board
/// write is any `save_issue` at all — and it is a trap for a GENERAL RUNNER,
/// where every call in the session arrives under one tool name. Such a row does
/// not merely over-record: it reports [`Outcome::Blocked`] for every unrelated
/// command that lacks its result paths, which is a could-not-look filed against
/// calls the author never meant, and the noise the ordering above exists to
/// keep out arriving by the one route ordering cannot stop.
///
/// **Stated rather than gated, and the gap is named rather than papered over**
/// (non-negotiable rule 2's honest half). A load-time refusal would have to know
/// which tool names are runners, and that is a consumer fact — a core carrying
/// the list would violate rule 1. The declaration a consumer CAN make is
/// `requires_input_matching`, and every row here over a runner carries one.
#[must_use]
pub fn outcome(declared: &Declared, context: &Context<'_>) -> Outcome {
    let selected = declared
        .refused_when_input
        .iter()
        .all(|path| scalar(context.input, path).is_none())
        && declared
            .refused_when_result
            .iter()
            .all(|path| scalar(context.result, path).is_none())
        && declared
            .requires_input_matching
            .iter()
            .all(|(path, pattern)| {
                // BOTH HALVES ARE COULD-NOT-LOOK, and could-not-look does not
                // match. An unresolvable path and a pattern id the table does not
                // carry are each a selector that failed to read its subject, and
                // recording anyway would file a row for a call nobody selected.
                // The pattern id is refused at LOAD, so the second arm is
                // unreachable for a config that loaded and is written for the one
                // that reached here another way.
                let Some(text) = scalar(context.input, path) else {
                    return false;
                };
                context
                    .patterns
                    .get(pattern)
                    .is_some_and(|regex| regex.is_match(&text))
            });
    if !selected {
        return Outcome::NotSelected;
    }
    if declared
        .requires
        .iter()
        .all(|path| scalar(context.result, path).is_some())
    {
        return Outcome::Applies;
    }
    Outcome::Blocked(BLOCKED_REQUIRED_ABSENT)
}

/// The single scalar a dotted path selects, as a bare string.
///
/// `None` for anything that is not exactly one non-null scalar, so a caller can
/// never write a JSON fragment into a record a positional reader parses —
/// [`crate::mint::scalar`]'s rule, and it matters more here because this record's
/// columns are positional by construction.
fn scalar(value: &serde_json::Value, path: &str) -> Option<String> {
    let mut current = value;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    match current {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Bool(_) | serde_json::Value::Number(_) => Some(current.to_string()),
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => {
            None
        }
    }
}

/// Every string an iterating path yields.
fn strings(value: &serde_json::Value, path: &str) -> Vec<String> {
    let (name, iterate) = match path.strip_suffix("[]") {
        Some(name) => (name, true),
        None => (path, false),
    };
    let mut current = value;
    for segment in name.split('.') {
        let Some(next) = current.get(segment) else {
            return Vec::new();
        };
        current = next;
    }
    if !iterate {
        return current.as_str().map(str::to_owned).into_iter().collect();
    }
    current
        .as_array()
        .map(|values| {
            values
                .iter()
                .filter_map(|value| value.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// What an expression is evaluated against.
///
/// Assembled once at the boundary and handed down, so [`evaluate`] stays a pure
/// function of its inputs and is testable without a world — the rule every other
/// render path in this crate follows.
#[derive(Debug)]
pub struct Context<'a> {
    /// What the far end stored. The unforgeable half.
    pub result: &'a serde_json::Value,
    /// What the caller asked for.
    pub input: &'a serde_json::Value,
    /// The programs the committed config declares, by id.
    pub programs: &'a BTreeMap<String, Program>,
    /// The patterns the committed config declares, by id.
    pub patterns: &'a BTreeMap<String, regex::Regex>,
    /// The Ready grammar those patterns resolve to, where they resolve at all.
    ///
    /// `None` is could-not-look and never a clean answer: a consumer whose
    /// `[[pattern]]` table is missing a row [`crate::ready::REQUIRED_PATTERNS`]
    /// names has no grammar, so a column asking [`Ask::Ready`] records `-`
    /// rather than a verdict nothing could compute. Resolved once at the
    /// boundary, for [`Context`]'s own reason — [`evaluate`] stays a pure
    /// function of its inputs.
    pub grammar: Option<&'a crate::ready::Grammar>,
    /// Where a relative program path resolves against.
    pub root: &'a Path,
    /// The branch the record is keyed by, where the clone is on one.
    ///
    /// `None` on a detached HEAD, and [`Value::Branch`] renders that as
    /// could-not-look rather than as a name. Carried on the context rather than
    /// resolved inside [`evaluate`] for this struct's whole reason: the function
    /// stays a pure function of its inputs and needs no world to test.
    pub branch: Option<&'a str>,
    /// The instant a column that grades a lifetime compares against.
    ///
    /// **The clock is the BOUNDARY'S, never the decision's**, which is the same
    /// rule `.claude/rules/policy-modules.md` states for why no policy module
    /// sees a timestamp and `crate::config_model::Rule::max_age` states for a receipt's
    /// age. Carried here rather than read inside [`evaluate`] for [`Context`]'s
    /// whole reason — the function stays a pure function of its inputs — and it
    /// is what makes two evaluations over one lease produce one answer.
    pub now: i64,
}

/// Evaluate one expression, or `None` where it could not be resolved.
///
/// `None` is *could not look* end to end: it propagates through [`Value::Object`]
/// as an omitted key rather than as a null, because the censused consumer of that
/// object treats an absent key and a present-but-empty one as different answers
/// (an empty-but-present relation set asserts *this row has no blockers*, which is
/// a claim nothing here checked).
#[must_use]
pub fn evaluate(value: &Value, context: &Context<'_>) -> Option<serde_json::Value> {
    match value {
        Value::Literal(text) => Some(serde_json::Value::String(text.clone())),
        Value::Branch => context
            .branch
            .map(|branch| serde_json::Value::String(branch.to_owned())),
        Value::Inputs(paths) => Some(serde_json::Value::String(
            paths
                .iter()
                .flat_map(|path| strings(context.input, path))
                .collect::<Vec<String>>()
                .join(" "),
        )),
        Value::Result(path) => scalar(context.result, path).map(serde_json::Value::String),
        Value::Input(path) => scalar(context.input, path).map(serde_json::Value::String),
        Value::Object(fields) => {
            let mut object = serde_json::Map::new();
            for (key, expression) in fields {
                if let Some(rendered) = evaluate(expression, context) {
                    object.insert(key.clone(), rendered);
                }
            }
            Some(serde_json::Value::Object(object))
        }
        Value::Wrap { from, key } => Some(serde_json::Value::Array(
            strings(context.input, from)
                .into_iter()
                .map(|element| {
                    let mut object = serde_json::Map::new();
                    object.insert(key.clone(), serde_json::Value::String(element));
                    serde_json::Value::Object(object)
                })
                .collect(),
        )),
        Value::Section {
            from,
            label,
            select,
        } => {
            let text = as_text(&evaluate(from, context)?)?;
            let label = context.patterns.get(label)?;
            let select = context.patterns.get(select)?;
            let span = section(&text, label, select);
            if span.is_empty() {
                return None;
            }
            Some(serde_json::Value::String(span))
        }
        Value::Program { run, stdin, read } => {
            let declared = context.programs.get(run)?;
            let payload = as_text(&evaluate(stdin, context)?)?;
            let (status, out) = run_program(context.root, declared, &payload)?;
            read_back(read, status, &out)
        }
        Value::Authority { ask, stdin, read } => {
            let payload = evaluate(stdin, context)?;
            let (status, out) = match ask {
                Ask::Ready => crate::ready::adjudicate(context.grammar?, &payload, context.root)?,
                // THE PAYLOAD IS UNREAD ON BOTH LEASE ARMS, and that is a
                // property of the subject rather than an oversight: the lease
                // lives on a remote ref, so there is nothing about a tool result
                // for it to judge. `stdin` is still evaluated above, because a
                // column whose expression could not resolve must record
                // could-not-look rather than quietly answering about the lease.
                Ask::LeaseStatus => crate::lease::adjudicate(
                    crate::lease::Asked::Status,
                    context.root,
                    context.now,
                )?,
                Ask::LeaseSuccessor => crate::lease::adjudicate(
                    crate::lease::Asked::Successor,
                    context.root,
                    context.now,
                )?,
                // The payload IS the subject here, unlike both lease arms: the
                // question is about the body the tracker stored.
                Ask::NamedPaths => crate::ready::named_paths(&payload, context.root)?,
                Ask::ClosingKeys => {
                    let text = as_text(&payload)?;
                    let lines: String = context
                        .grammar?
                        .keys_closed_in(&text)
                        .iter()
                        .flat_map(|key| [key.as_str(), "\n"])
                        .collect();
                    (0, lines)
                }
            };
            read_back(read, status, &out)
        }
    }
}

/// One answer read back out of a status and a stdout, whichever produced them.
///
/// Shared by the spawning and the compiled arms so the two cannot drift: a column
/// switched from one to the other must keep its `read` table's meaning exactly,
/// and two copies of this match is where that guarantee would quietly stop
/// holding.
fn read_back(read: &Read, status: i32, out: &str) -> Option<serde_json::Value> {
    match read {
        Read::Status(map) => map
            .get(&status.to_string())
            .cloned()
            .map(serde_json::Value::String),
        Read::Stdout => Some(serde_json::Value::String(out.to_owned())),
        Read::StdoutLine(prefix) => out
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .map(|rest| serde_json::Value::String(rest.to_owned())),
    }
}

/// An evaluated value as the text a program reads on stdin.
///
/// A string is itself; anything else is its compact JSON. That split is what lets
/// one `stdin` slot carry both a bare body and an assembled payload without the
/// consumer declaring which.
fn as_text(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(text) => Some(text.clone()),
        serde_json::Value::Null => None,
        other => serde_json::to_string(other).ok(),
    }
}

/// The lines from a label matching `select` until the next label matching
/// `label`.
///
/// `in_span` is re-decided on EVERY label rather than only on the first, because
/// a structured block's clauses are siblings: the next label ends the span
/// whether or not it is the one wanted.
fn section(text: &str, label: &regex::Regex, select: &regex::Regex) -> String {
    let mut kept: Vec<&str> = Vec::new();
    let mut in_span = false;
    for line in text.lines() {
        if label.is_match(line) {
            in_span = select.is_match(line);
        }
        if in_span {
            kept.push(line);
        }
    }
    kept.join("\n")
}

/// Run a declared program with `payload` on stdin, and read back its status and
/// stdout.
///
/// **stderr is discarded, deliberately.** Every program a recorder runs is a gate
/// whose stderr is its own pointer report, and this module prints nothing — a
/// recorder that surfaced another gate's findings would be a second, unasked-for
/// channel for them. That bound, and the spawn, are [`crate::exec::piped`]'s:
/// this module is not a placed adapter (`policy/spawn-adapters.rego`), and it
/// runs the gates this repository already owns because the value it records IS
/// their verdict. Bounded three ways — only a program the committed config
/// names, only once the tool selector matched, and only with the stdin this
/// module assembled — so almost every tool result reaches none of it. It stays a
/// spawn rather than becoming a port because the censused program is the single
/// authority on a grammar 19 other files share.
fn run_program(root: &Path, program: &Program, payload: &str) -> Option<(i32, String)> {
    crate::exec::piped(root, Path::new(&program.path), &program.args, payload)
}

/// One column's rendered token.
///
/// Whitespace is folded to a single `,` LAST, after every set operation, so a
/// column is one field however many tokens it carries — the property that lets a
/// record grow a column without the previous one swallowing it.
#[must_use]
pub fn render_column(column: &Column, context: &Context<'_>) -> String {
    let Some(value) = evaluate(&column.value, context) else {
        return String::from(ABSENT);
    };
    let Some(text) = as_text(&value) else {
        return String::from(ABSENT);
    };
    let mut tokens: Vec<String> = text.split_whitespace().map(str::to_owned).collect();
    if let Some(minus) = &column.minus {
        let removed: Vec<String> = evaluate(minus, context)
            .as_ref()
            .and_then(as_text)
            .map(|text| text.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        tokens.retain(|token| !removed.contains(token));
    }
    if let Some(dropped) = column
        .without
        .as_ref()
        .and_then(|without| evaluate(without, context))
        .as_ref()
        .and_then(as_text)
    {
        tokens.retain(|token| *token != dropped);
    }
    if tokens.is_empty() {
        // The three-valued read, and the only place it is decided. A column that
        // asked for a count says `0`; one that did not says could-not-look.
        return String::from(if column.zero_is_a_count { "0" } else { ABSENT });
    }
    let joined = tokens.join(",");
    match &column.counted_with {
        Some(separator) => format!("{}{separator}{joined}", tokens.len()),
        None => joined,
    }
}

/// The whole record line this result earns, or `None` where it earns none.
#[must_use]
pub fn render(declared: &Declared, context: &Context<'_>) -> Option<String> {
    if !satisfied(declared, context) {
        return None;
    }
    Some(
        declared
            .columns
            .iter()
            .map(|column| render_column(column, context))
            .collect::<Vec<String>>()
            .join(" "),
    )
}

/// Append every record this result earns, and report how many were written.
///
/// **`git_dir`, never the cwd**, which is a measured defect rather than a style
/// choice: a hook inherits the cwd of the tool call, which is not required to be
/// inside this project. `record_mints` states the same rule one module over and
/// is why the capture store kept working while a cwd-rooted reader wrote nothing.
///
/// Every failure is silent per the module doc. The return value is for a caller
/// that wants to count, never for a verdict — a recorder decides nothing.
pub fn append_all(
    recorders: &[Declared],
    git_dir: &Path,
    branch: &str,
    context: &Context<'_>,
    selects: impl Fn(&str, &str) -> bool,
    tool: &str,
) -> usize {
    let mut written = 0;
    // THE CLAIM PARTITIONS THE RECORD (CLOUD-1300), resolved once here rather than
    // per row: every row on this call writes under the same attempt, and re-reading
    // the receipt per row would let a claim minted mid-loop split one call's lines
    // across two files.
    let claim = crate::claim::claimed_token(&git_dir.join("batten-receipts"), branch);
    // THE SNAPSHOT IS TAKEN ONCE, BEFORE ANY APPEND, and that is a correctness
    // property rather than an economy. Several rows write one record, so a row
    // evaluated later in this loop would otherwise read what an earlier row just
    // wrote — and "already recorded" would come to mean "recorded a moment ago by
    // this very call". Measured: the create row appended, and the groom row then
    // matched its own create and appended a second line for one write. The shell
    // this replaces could not have the bug, because it was one program deciding
    // once; splitting it into rows is what introduced the ordering.
    let mut snapshots: BTreeMap<String, String> = BTreeMap::new();
    for recorder in recorders {
        if !selects(&recorder.tool, tool) {
            continue;
        }
        let RecordKey::Branch = recorder.key;
        let path = record_path(git_dir, &recorder.record, branch, claim.as_deref());
        if !snapshots.contains_key(&recorder.record) {
            snapshots.insert(
                recorder.record.clone(),
                crate::fsio::read_to_string(&path).unwrap_or_default(),
            );
        }
        if let Some(recorded) = &recorder.requires_recorded
            && !already_recorded(
                snapshots.get(&recorder.record).map_or("", String::as_str),
                recorded,
                context,
            )
        {
            continue;
        }
        // COULD-NOT-LOOK IS WRITTEN, NOT SKIPPED (CLOUD-1126). A row whose
        // selector matched a call that did not answer it is the one arm a
        // downstream gate cannot re-derive: the call is gone by the time anything
        // reads the record, and its absence looks exactly like a clean run.
        if let Outcome::Blocked(reason) = outcome(recorder, context) {
            append(
                &blocked_path(git_dir, branch, claim.as_deref()),
                &format!("{} {reason}", recorder.name),
            );
            continue;
        }
        let Some(line) = render(recorder, context) else {
            continue;
        };
        if append(&path, &line).is_some() {
            written += 1;
        }
    }
    written
}

/// Where this branch's recorder could-not-look lines live (CLOUD-1126).
///
/// A file of its own rather than a reserved record name, because a record name is
/// the consumer's — `[[recorder]] record = "blocked"` is a config a consumer may
/// legitimately write, and a channel that collided with it would silently merge
/// the engine's report with theirs. Partitioned by the branch's claim exactly as
/// [`record_path`] is, and for the same reason: a stale attempt's could-not-look
/// is not evidence about this one.
///
/// Each line is `<recorder-id> <reason-class>` — two pointers, and never a byte
/// of what the call produced.
#[must_use]
pub fn blocked_path(git_dir: &Path, branch: &str, claim: Option<&str>) -> std::path::PathBuf {
    git_dir
        .join("batten-receipts")
        .join(receipt_name("recorder-blocked", branch, claim))
}

/// The longest receipt name written whole (CLOUD-2706), well under the
/// 255-byte component limit every filesystem here has.
const MAX_RECEIPT_NAME: usize = 200;

/// `<record>.<branch>.<claim>`, or `<record>.<branch>` for an unclaimed branch.
///
/// **A CLAIM TOO LONG FOR A FILE NAME IS DIGESTED (CLOUD-2706).** The claim joins
/// every key the branch claimed, and one PR carrying a bundle of rows is the
/// shape the workflow prescribes: 34 keys passed the 255-byte limit and every
/// claim-keyed write exited 3. The digest is deterministic, so writers and
/// readers agree, and the name keeps its `<record>.<branch>.` prefix, which is
/// what `land`'s branch sweep matches. A name within the limit is unchanged.
fn receipt_name(record: &str, branch: &str, claim: Option<&str>) -> String {
    use sha2::Digest as _;
    use std::fmt::Write as _;
    let branch = branch.replace('/', "-");
    match claim {
        Some(claim) => {
            let whole = format!("{record}.{branch}.{claim}");
            if whole.len() <= MAX_RECEIPT_NAME {
                return whole;
            }
            let digest = sha2::Sha256::digest(claim.as_bytes());
            let hex = digest.iter().take(8).fold(String::new(), |mut hex, byte| {
                let _ = write!(hex, "{byte:02x}");
                hex
            });
            format!("{record}.{branch}.claim-{hex}")
        }
        None => format!("{record}.{branch}"),
    }
}

/// Where a branch-keyed record lives.
///
/// The `/`→`-` fold is the one every other branch-keyed receipt here takes, and
/// it must match byte for byte: a reader looking under a different spelling finds
/// no file and passes everything, which is the silent direction.
///
/// **PARTITIONED BY THE BRANCH'S CLAIM, NOT BY THE BRANCH ALONE (CLOUD-1300).** A
/// branch name outlives the branch it described, so keying on the name alone let
/// the next attempt read the previous one's lines as its own — measured, where a
/// `pr-closes` record still named a merged PR's keys and `issue file same`'s
/// exemption was evaluated against them. That direction is the dangerous one: it
/// exempts silently, and nothing downstream re-checks.
///
/// `claim` is [`crate::claim::claimed_token`]'s answer, and `None` is
/// could-not-look. **An unclaimed branch keeps the OLD path**, which is what makes
/// this a partition rather than a migration: nothing that could not be attributed
/// is moved, and a reader of an unclaimed branch sees exactly what it saw before.
#[must_use]
pub fn record_path(
    git_dir: &Path,
    record: &str,
    branch: &str,
    claim: Option<&str>,
) -> std::path::PathBuf {
    git_dir
        .join("batten-receipts")
        .join(receipt_name(record, branch, claim))
}

/// Whether the snapshot already carries a line matching EVERY named column.
///
/// A record that could not be read is the empty snapshot, so nothing matches and
/// nothing is written. That is the fail-closed direction for a WRITE, and it is
/// deliberately the opposite of how the gate reading this record fails: writing
/// less can only make a later gate quieter, while writing on an unestablished
/// precondition would record a judgement nothing supports.
///
/// Every column must match, never any: the columns together are the anchor, and
/// matching on one of them is what let a comment line stand in for a filing.
fn already_recorded(snapshot: &str, recorded: &Recorded, context: &Context<'_>) -> bool {
    let wanted: Option<Vec<(usize, String)>> = recorded
        .matches
        .iter()
        .map(|(column, value)| {
            evaluate(value, context)
                .as_ref()
                .and_then(as_text)
                .map(|text| (*column, text))
        })
        .collect();
    let Some(wanted) = wanted else {
        return false;
    };
    snapshot.lines().any(|line| {
        let columns: Vec<&str> = line.split_whitespace().collect();
        wanted
            .iter()
            .all(|(at, text)| columns.get(*at).is_some_and(|column| column == text))
    })
}

/// Append one line, creating the store if it does not exist.
fn append(path: &Path, line: &str) -> Option<()> {
    std::fs::create_dir_all(path.parent()?).ok()?;
    crate::durable::append(path, line).ok()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a test literal that does not compile is a broken test, not a reachable path"
)]
mod outcome_tests {
    use super::*;
    #[cfg(test)]

    /// A claim of a whole bundle of keys stays a legal file name (CLOUD-2706).
    #[test]
    fn a_claim_too_long_for_a_file_name_is_digested() {
        let keys: Vec<String> = (1560..1594).map(|n| format!("CLOUD-{n}")).collect();
        let claim = keys.join("-");
        let name = |claim: &str| {
            record_path(
                Path::new("/g"),
                "pr-unsubscribed",
                "claude/bundle",
                Some(claim),
            )
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
        };
        let long = name(&claim);
        assert!(long.len() <= MAX_RECEIPT_NAME, "{long}");
        assert!(long.starts_with("pr-unsubscribed.claude-bundle."), "{long}");
        assert_eq!(long, name(&claim), "the same claim names the same file");
        assert_ne!(long, name(&format!("{claim}-CLOUD-9999")));
        assert_eq!(name("CLOUD-1"), "pr-unsubscribed.claude-bundle.CLOUD-1");
    }

    fn declared(requires: &[&str], matching: &[(&str, &str)]) -> Declared {
        Declared {
            name: "r".to_owned(),
            record: "r".to_owned(),
            tool: "Bash".to_owned(),
            key: RecordKey::Branch,
            requires: requires.iter().map(|path| (*path).to_owned()).collect(),
            refused_when_input: Vec::new(),
            refused_when_result: Vec::new(),
            requires_input_matching: matching
                .iter()
                .map(|(path, pattern)| ((*path).to_owned(), (*pattern).to_owned()))
                .collect(),
            requires_recorded: None,
            columns: Vec::new(),
        }
    }

    /// CLOUD-1126's three-valued read, over the two arms that used to be one.
    ///
    /// The measured shape: the row selects a command and reads its `stdout`. A
    /// call that matched and produced no stdout is could-not-look; a call the
    /// pattern never matched is simply not this row's, and reporting it would
    /// file a finding for every unrelated tool call in the session.
    #[test]
    fn a_selected_call_that_does_not_answer_is_blocked_and_an_unselected_one_is_not() {
        let mut patterns = std::collections::BTreeMap::new();
        patterns.insert(
            "fetch".to_owned(),
            regex::Regex::new("gh pr view").expect("a test literal compiles"),
        );
        let programs = std::collections::BTreeMap::new();
        let selected = serde_json::json!({"command": "gh pr view --json body"});
        let unselected = serde_json::json!({"command": "ls -la"});
        let empty = serde_json::json!({});
        let answered = serde_json::json!({"stdout": "Closes CLOUD-1"});
        let row = declared(&["stdout"], &[("command", "fetch")]);

        let context =
            |input: &'static serde_json::Value, result: &'static serde_json::Value| Context {
                input,
                result,
                branch: Some("work"),
                root: Path::new("."),
                patterns: &patterns,
                programs: &programs,
                grammar: None,
                // FIXED, because this row grades no lifetime. `now` reached
                // `Context` on trunk while this case was on a branch, and the
                // rebase merged the two without a textual conflict; the value
                // is unread here, so a clock would only make the case
                // non-deterministic for nothing.
                now: 0,
            };
        let _ = &context;

        let blocked = Context {
            input: &selected,
            result: &empty,
            branch: Some("work"),
            root: Path::new("."),
            patterns: &patterns,
            programs: &programs,
            grammar: None,
            now: 0,
        };
        assert_eq!(
            outcome(&row, &blocked),
            Outcome::Blocked(BLOCKED_REQUIRED_ABSENT),
            "the row's subject arrived and the call produced none of what it reads"
        );

        let missed = Context {
            input: &unselected,
            result: &empty,
            branch: Some("work"),
            root: Path::new("."),
            patterns: &patterns,
            programs: &programs,
            grammar: None,
            now: 0,
        };
        assert_eq!(
            outcome(&row, &missed),
            Outcome::NotSelected,
            "a call this row was never about carries no information, however many \
             required paths are missing"
        );

        let applies = Context {
            input: &selected,
            result: &answered,
            branch: Some("work"),
            root: Path::new("."),
            patterns: &patterns,
            programs: &programs,
            grammar: None,
            now: 0,
        };
        assert_eq!(outcome(&row, &applies), Outcome::Applies);
        assert!(satisfied(&row, &applies));
        assert!(!satisfied(&row, &blocked));
    }

    /// CLOUD-2214: a backgrounded call's `stdout` is the host's placeholder, so
    /// a row refusing `backgroundTaskId` does not read it as the command's.
    #[test]
    fn a_backgrounded_result_is_not_recorded() {
        let mut patterns = std::collections::BTreeMap::new();
        patterns.insert(
            "fetch".to_owned(),
            regex::Regex::new("gh pr view").expect("a test literal compiles"),
        );
        let programs = std::collections::BTreeMap::new();
        let input = serde_json::json!({"command": "gh pr view --json body"});
        let backgrounded = serde_json::json!({
            "stdout": "Command running in background with ID: b1.",
            "backgroundTaskId": "b1",
        });
        let foreground = serde_json::json!({"stdout": "Closes CLOUD-1"});
        let mut row = declared(&["stdout"], &[("command", "fetch")]);
        row.refused_when_result = vec!["backgroundTaskId".to_owned()];
        let context = |result| Context {
            input: &input,
            result,
            branch: Some("work"),
            root: Path::new("."),
            patterns: &patterns,
            programs: &programs,
            grammar: None,
            now: 0,
        };
        assert_eq!(outcome(&row, &context(&backgrounded)), Outcome::NotSelected);
        assert_eq!(outcome(&row, &context(&foreground)), Outcome::Applies);
    }

    /// A context over `input` and `result` with the given tables, rooted at
    /// `root`. `now` is fixed: nothing here grades a lifetime.
    fn context_over<'a>(
        input: &'a serde_json::Value,
        result: &'a serde_json::Value,
        programs: &'a BTreeMap<String, Program>,
        patterns: &'a BTreeMap<String, regex::Regex>,
        root: &'a Path,
    ) -> Context<'a> {
        Context {
            result,
            input,
            programs,
            patterns,
            grammar: None,
            root,
            branch: Some("work"),
            now: 0,
        }
    }

    /// A row on `Bash` writing `record` with one literal column.
    fn literal_row(name: &str, record: &str, tool: &str, text: &str) -> Declared {
        let mut row = declared(&[], &[]);
        row.name = name.to_owned();
        row.record = record.to_owned();
        row.tool = tool.to_owned();
        row.columns = vec![column(Value::Literal(text.to_owned()))];
        row
    }

    fn column(value: Value) -> Column {
        Column {
            name: "c".to_owned(),
            value,
            minus: None,
            without: None,
            counted_with: None,
            zero_is_a_count: false,
        }
    }

    /// Fails by: an iterating path read as a scalar or the reverse, or any
    /// yield other than exactly the strings the path selects.
    #[test]
    fn strings_yields_exactly_what_the_path_selects() {
        let value = serde_json::json!({"a": {"list": ["x", 1, "y"], "one": "s"}});
        assert_eq!(strings(&value, "a.list[]"), vec!["x", "y"]);
        assert_eq!(strings(&value, "a.one"), vec!["s"]);
        assert_eq!(strings(&value, "a.one[]"), Vec::<String>::new());
        assert_eq!(strings(&value, "a.missing[]"), Vec::<String>::new());
    }

    /// Fails by: a value rendered as some other text, a null read as text, or
    /// a section that keeps the wrong span.
    #[test]
    fn text_and_section_read_exactly_their_span() {
        assert_eq!(as_text(&serde_json::json!("body")), Some("body".to_owned()));
        assert_eq!(as_text(&serde_json::Value::Null), None);
        assert_eq!(
            as_text(&serde_json::json!({"k": 1})),
            Some(r#"{"k":1}"#.to_owned())
        );
        let label = regex::Regex::new("^## ").expect("a test literal compiles");
        let select = regex::Regex::new("^## Want").expect("a test literal compiles");
        let text = "intro\n## Other\nno\n## Want\nyes\nalso\n## Later\nno";
        assert_eq!(section(text, &label, &select), "## Want\nyes\nalso");
    }

    /// Fails by: an evaluation that resolves to nothing or to a null, or a read
    /// table that answers for a status it does not map.
    #[test]
    fn evaluate_and_read_back_answer_exactly() {
        let programs = BTreeMap::new();
        let patterns = BTreeMap::new();
        let input = serde_json::json!({"ids": ["A", "B"]});
        let result = serde_json::json!({"id": "R"});
        let root = Path::new(".");
        let context = context_over(&input, &result, &programs, &patterns, root);
        assert_eq!(
            evaluate(&Value::Literal("k".to_owned()), &context),
            Some(serde_json::json!("k"))
        );
        assert_eq!(
            evaluate(&Value::Inputs(vec!["ids[]".to_owned()]), &context),
            Some(serde_json::json!("A B"))
        );
        let mut map = BTreeMap::new();
        map.insert("0".to_owned(), "pass".to_owned());
        let status = Read::Status(map);
        assert_eq!(read_back(&status, 0, ""), Some(serde_json::json!("pass")));
        assert_eq!(read_back(&status, 1, ""), None);
        let line = Read::StdoutLine("n=".to_owned());
        assert_eq!(
            read_back(&line, 0, "x\nn=3\n"),
            Some(serde_json::json!("3"))
        );
        assert_eq!(read_back(&line, 0, "x\n"), None);
    }

    /// Fails by: a declared program whose status or stdout is not the one it
    /// produced reaching the record.
    #[test]
    fn a_declared_program_answers_with_its_own_status_and_stdout() {
        if !cfg!(unix) {
            // Off unix there is no `sh` to run the declared program's script.
            return;
        }
        let dir = crate::scratch::scratch("recorder-run-program");
        let script = dir.join("echo.sh");
        std::fs::write(&script, "#!/bin/sh\ncat\nexit 3\n").expect("script");
        crate::engine::make_executable(&script).expect("mode");
        let program = Program {
            path: "echo.sh".to_owned(),
            args: Vec::new(),
        };
        assert_eq!(
            run_program(&dir, &program, "payload"),
            Some((3, "payload".to_owned()))
        );
    }

    /// Fails by: a set difference that keeps what it removes, a `without` that
    /// keeps only the dropped token, or a rendered line that is not exactly the
    /// joined columns.
    #[test]
    fn a_column_renders_its_tokens_after_every_set_operation() {
        let programs = BTreeMap::new();
        let patterns = BTreeMap::new();
        let input = serde_json::json!({});
        let result = serde_json::json!({});
        let context = context_over(&input, &result, &programs, &patterns, Path::new("."));
        let mut col = column(Value::Literal("a b c d".to_owned()));
        col.minus = Some(Value::Literal("b".to_owned()));
        col.without = Some(Value::Literal("c".to_owned()));
        assert_eq!(render_column(&col, &context), "a,d");
        col.counted_with = Some(":".to_owned());
        assert_eq!(render_column(&col, &context), "2:a,d");
        col.minus = Some(Value::Literal("a b d".to_owned()));
        assert_eq!(render_column(&col, &context), ABSENT);
        col.zero_is_a_count = true;
        assert_eq!(render_column(&col, &context), "0");

        let mut row = literal_row("r", "rec", "Bash", "one");
        row.columns.push(column(Value::Literal("two".to_owned())));
        assert_eq!(render(&row, &context), Some("one two".to_owned()));
        row.requires = vec!["absent".to_owned()];
        assert_eq!(render(&row, &context), None);
    }

    /// Fails by: any load refusal admitting what it refuses, or refusing the
    /// well-formed row beside it.
    #[test]
    fn validate_admits_the_well_formed_and_refuses_each_dangling_id() {
        let mut programs = BTreeMap::new();
        programs.insert(
            "gate".to_owned(),
            Program {
                path: "gate".to_owned(),
                args: Vec::new(),
            },
        );
        let patterns: std::collections::BTreeSet<String> = ["p".to_owned()].into();
        let mut status = BTreeMap::new();
        status.insert("0".to_owned(), "ok".to_owned());
        let program = |run: &str, read: Read| Value::Program {
            run: run.to_owned(),
            stdin: Box::new(Value::Literal("x".to_owned())),
            read,
        };
        let section = |label: &str| Value::Section {
            from: Box::new(Value::Literal("x".to_owned())),
            label: label.to_owned(),
            select: "p".to_owned(),
        };

        let mut good = literal_row("good", "rec", "Bash", "k");
        good.requires_input_matching = [("command".to_owned(), "p".to_owned())].into();
        good.requires_recorded = Some(Recorded {
            matches: [(0, Value::Literal("k".to_owned()))].into(),
        });
        good.columns
            .push(column(program("gate", Read::Status(status.clone()))));
        good.columns.push(column(section("p")));
        let other = literal_row("other", "rec", "Bash", "k");
        assert!(validate(&[good.clone(), other], &programs, &patterns).is_ok());

        let refused = |row: Declared| validate(&[row], &programs, &patterns).is_err();
        assert!(validate(&[good.clone(), good.clone()], &programs, &patterns).is_err());
        let mut row = good.clone();
        row.requires_input_matching = [("command".to_owned(), "q".to_owned())].into();
        assert!(refused(row));
        let mut row = good.clone();
        row.requires_recorded = Some(Recorded {
            matches: [(row.columns.len(), Value::Literal("k".to_owned()))].into(),
        });
        assert!(refused(row));
        let mut row = good.clone();
        row.columns.push(column(section("q")));
        assert!(refused(row));
        let mut row = good.clone();
        row.columns.push(column(program("absent", Read::Stdout)));
        assert!(refused(row));
        let mut row = good.clone();
        row.columns
            .push(column(program("gate", Read::Status(BTreeMap::new()))));
        assert!(refused(row));
        let mut row = good;
        let mut unparsed = BTreeMap::new();
        unparsed.insert("zero".to_owned(), "ok".to_owned());
        row.columns
            .push(column(program("gate", Read::Status(unparsed))));
        assert!(refused(row));
    }

    /// Fails by: a path that does not fold the branch, drop the claim, or
    /// partition by it.
    #[test]
    fn record_and_blocked_paths_fold_the_branch_and_partition_by_claim() {
        let git = Path::new("g");
        let receipts = git.join("batten-receipts");
        assert_eq!(
            record_path(git, "rec", "a/b", Some("c")),
            receipts.join("rec.a-b.c")
        );
        assert_eq!(
            record_path(git, "rec", "a/b", None),
            receipts.join("rec.a-b")
        );
        assert_eq!(
            blocked_path(git, "a/b", Some("c")),
            receipts.join("recorder-blocked.a-b.c")
        );
        assert_eq!(
            blocked_path(git, "a/b", None),
            receipts.join("recorder-blocked.a-b")
        );
    }

    /// Fails by: a precondition that matches a line missing one of its
    /// columns, or misses the line carrying all of them.
    #[test]
    fn already_recorded_needs_every_named_column_on_one_line() {
        let programs = BTreeMap::new();
        let patterns = BTreeMap::new();
        let input = serde_json::json!({});
        let result = serde_json::json!({});
        let context = context_over(&input, &result, &programs, &patterns, Path::new("."));
        let recorded = Recorded {
            matches: [
                (0, Value::Literal("issue".to_owned())),
                (1, Value::Literal("K-1".to_owned())),
            ]
            .into(),
        };
        assert!(already_recorded(
            "comment K-1\nissue K-1 x\n",
            &recorded,
            &context
        ));
        assert!(!already_recorded(
            "comment K-1\nissue K-2\n",
            &recorded,
            &context
        ));
        assert!(!already_recorded("", &recorded, &context));
    }

    /// Fails by: a row selected that should not be, a snapshot that is not
    /// taken before the first append, a precondition read inverted, or a count
    /// that is not the number of lines written.
    #[test]
    fn append_all_writes_each_earned_line_against_the_snapshot_and_counts_them() {
        let git_dir = crate::scratch::scratch("recorder-append-all");
        let programs = BTreeMap::new();
        let patterns = BTreeMap::new();
        let input = serde_json::json!({});
        let result = serde_json::json!({});
        let context = context_over(&input, &result, &programs, &patterns, &git_dir);
        let mut follow = literal_row("follow", "rec", "Bash", "two");
        follow.requires_recorded = Some(Recorded {
            matches: [(0, Value::Literal("one".to_owned()))].into(),
        });
        let rows = [
            literal_row("first", "rec", "Bash", "one"),
            literal_row("unselected", "rec", "Other", "other"),
            follow,
        ];
        let selects = |declared: &str, called: &str| declared == called;
        let path = record_path(&git_dir, "rec", "main", None);

        // Empty record: `follow`'s precondition reads the snapshot taken before
        // `first` appended, so only `first` writes.
        assert_eq!(
            append_all(&rows, &git_dir, "main", &context, selects, "Bash"),
            1
        );
        assert_eq!(crate::fsio::read_to_string(&path).expect("record"), "one\n");

        // Now the snapshot carries `one`, so both earn a line.
        assert_eq!(
            append_all(&rows, &git_dir, "main", &context, selects, "Bash"),
            2
        );
        assert_eq!(
            crate::fsio::read_to_string(&path).expect("record"),
            "one\none\ntwo\n"
        );
    }
}
