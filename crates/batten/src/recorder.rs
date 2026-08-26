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
use std::io::Write as _;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// The token every unresolvable value renders as.
///
/// Shared with [`crate::mint::ABSENT`]'s reasoning rather than its constant,
/// because the two modules write different records and a reader of either needs
/// the same three-valued read: a column that is `-` is *could not look*, never
/// *looked and found nothing*. Collapsing those is the CLOUD-251 shape every
/// record here is careful to avoid.
pub const ABSENT: &str = "-";

/// How a record is filed.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize, schemars::JsonSchema,
)]
#[serde(rename_all = "kebab-case")]
pub enum RecordKey {
    /// Filed under the current branch, so every commit on it continues to serve
    /// the same record.
    Branch,
}

/// One recorder this repository declares.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Declared {
    /// The record namespace — the file this writes, and the file the rule that
    /// reads it names.
    pub name: String,
    /// Which tool's result records, matched by [`crate::rules::selects_tool_name`].
    ///
    /// A tool name, never a field shape, for [`crate::mint::Declared::tool`]'s
    /// measured reason: a connector is exposed under more than one name over its
    /// lifetime (CLOUD-178), and a write response and a read payload are
    /// shape-identical across the fields either carries.
    pub tool: String,
    /// What the record is filed under.
    pub key: RecordKey,
    /// Paths into the RESULT that must resolve for anything to be written.
    ///
    /// The success predicate, exactly as [`crate::mint::satisfied`] is: a result
    /// that does not carry these is a call that did not do the thing, and
    /// recording it would put a row in the journal for work nobody did.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<String>,
    /// Paths into the INPUT that must NOT resolve for anything to be written.
    ///
    /// The censused use is telling a create from an update: an update carries an
    /// id the create cannot, so a recorder that only wants creates declares the
    /// id here rather than needing a negation operator in the expression
    /// language.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused_when_input: Vec<String>,
    /// The columns, in order, space-joined into one line.
    ///
    /// **Every column renders exactly one whitespace-free token.** A record a
    /// positional reader can parse cannot have a variable-width field before its
    /// last, and the shell recorder this replaces learned that the hard way — its
    /// fifth column swallowed the sixth until the join moved to write time. So
    /// [`render_column`] folds whitespace rather than trusting a template not to
    /// produce any.
    pub columns: Vec<Column>,
}

/// One column of a record.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Column {
    /// What this column is called. Never read by the engine — it is what makes
    /// the config legible and what a finding can point at.
    pub name: String,
    /// The expression whose value this column carries.
    pub value: Value,
    /// Remove, from this column's whitespace-separated tokens, every token the
    /// named expression yields.
    ///
    /// The censused use is *"the rows the stored body cites that the caller
    /// passed as no relation"* — a set difference between what a program emitted
    /// and what the input carried. Expressed as a column operation rather than a
    /// [`Value`] variant because it is about the rendered tokens, not about the
    /// JSON.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minus: Option<Value>,
    /// Drop this token if it equals the value of the named expression.
    ///
    /// The row's own key is not an edge to anywhere; without this the censused
    /// column counts every row as citing itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub without: Option<Value>,
    /// Render as `<count><separator><joined>` rather than as the tokens alone.
    ///
    /// **A count and a pointer, never the payload** (non-negotiable rule 4). The
    /// separator is the consumer's because the reader of the record is the
    /// consumer's too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counted_with: Option<String>,
    /// Render `0` rather than [`ABSENT`] when the expression resolved and yielded
    /// no tokens.
    ///
    /// **Zero is a count; `-` is could-not-look.** Collapsing the two is the one
    /// mistake this record shape cannot afford, because a gate downstream passes
    /// on `-` by design and would then pass on a real measurement of nothing.
    #[serde(default)]
    pub zero_is_a_count: bool,
}

/// An expression over the tool envelope and the programs this repository owns.
///
/// **Closed, for [`crate::mint::Piece`]'s reason**: an unrecognised form is a
/// load error, never a value that silently renders as itself and writes a record
/// nobody can read.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Value {
    /// A constant the consumer wrote. What a `kind` column is made of.
    Literal(String),
    /// The scalar at a dotted path into the tool RESULT.
    Result(String),
    /// The scalar at a dotted path into the tool INPUT.
    ///
    /// Separate from [`Value::Result`] rather than one path with a prefix,
    /// because the two differ in TRUST and the difference is the whole reason the
    /// censused recorder is unforgeable: the result is what the far end stored,
    /// the input is what the caller asked for. A consumer choosing between them
    /// is choosing whose word to take, and that choice should be spelled.
    Input(String),
    /// A JSON object built from named sub-expressions.
    Object(BTreeMap<String, Value>),
    /// Each string an iterating INPUT path yields, wrapped as `{<key>: value}`.
    ///
    /// The shape a relation list takes in the payload the censused verdict
    /// program reads. Generic because the key is the consumer's.
    Wrap {
        /// The iterating input path, e.g. `blockedBy[]`.
        from: String,
        /// The object key each element is filed under.
        key: String,
    },
    /// The lines of another expression's value from a label matching `select`
    /// until the next label matching `label`.
    ///
    /// **Both patterns are `[[pattern]]` ids, never inline regexes**, which is the
    /// same load-time refusal `.claude/rules/policy-modules.md` records for a
    /// policy module and for the same measured reason: one concept, one spelling.
    /// The censused use narrows a body to one clause of a structured block, and
    /// that block's grammar already has exactly one definition elsewhere.
    Section {
        /// The expression whose text is narrowed.
        from: Box<Value>,
        /// The pattern id every label matches — what ENDS a span.
        label: String,
        /// The pattern id the wanted label matches — what STARTS the span.
        select: String,
    },
    /// What a declared program said about another expression's value.
    Program {
        /// The program id, resolved through the consumer's `[program]` table.
        program: String,
        /// The expression whose rendered value is handed to the program on stdin.
        stdin: Box<Value>,
        /// What to read back.
        read: Read,
    },
}

/// What a recorder reads back from a program it ran.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Read {
    /// The exit status, mapped through a table the consumer wrote.
    ///
    /// **An unmapped status is [`ABSENT`], never a default verdict**, and the
    /// censused reason is exact: the program this replaces exits `0` for pass,
    /// `1` for a judgement and `2` for *could not judge*, so folding anything
    /// non-zero into the refusal would record a verdict about the ENVIRONMENT
    /// wearing the mask of a verdict about the subject.
    Status(BTreeMap<String, String>),
    /// Standard output, whole.
    Stdout,
    /// The remainder of the first stdout line carrying this prefix.
    ///
    /// **Absent is could-not-look; present-and-empty is the honest zero.** The
    /// censused producer emits its line BEFORE it branches on a verdict, so a
    /// missing line means it never got that far, and a present empty one means it
    /// looked and found nothing.
    StdoutLine(String),
}

/// One program a recorder may run.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Program {
    /// The path, repo-relative. Resolved against the repository root rather than
    /// the cwd for [`crate::lib`]'s measured reason: a hook inherits the cwd of
    /// the tool call, which is not required to be inside this project.
    pub path: String,
    /// Arguments, before stdin is written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

/// Whether every required result path resolved and no refusing input path did.
#[must_use]
pub fn satisfied(
    declared: &Declared,
    result: &serde_json::Value,
    input: &serde_json::Value,
) -> bool {
    declared
        .requires
        .iter()
        .all(|path| scalar(result, path).is_some())
        && declared
            .refused_when_input
            .iter()
            .all(|path| scalar(input, path).is_none())
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
    /// Where a relative program path resolves against.
    pub root: &'a Path,
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
        Value::Program {
            program,
            stdin,
            read,
        } => {
            let declared = context.programs.get(program)?;
            let payload = as_text(&evaluate(stdin, context)?)?;
            let (status, out) = run_program(context.root, declared, &payload)?;
            match read {
                Read::Status(map) => map
                    .get(&status.to_string())
                    .cloned()
                    .map(serde_json::Value::String),
                Read::Stdout => Some(serde_json::Value::String(out)),
                Read::StdoutLine(prefix) => out
                    .lines()
                    .find_map(|line| line.strip_prefix(prefix.as_str()))
                    .map(|rest| serde_json::Value::String(rest.to_owned())),
            }
        }
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
/// channel for them.
fn run_program(root: &Path, program: &Program, payload: &str) -> Option<(i32, String)> {
    #[expect(
        clippy::disallowed_types,
        reason = "stays — a recorder runs the gates this repository already owns, because the \
                  value it records IS their verdict (CLOUD-1051). Bounded three ways: only a \
                  program the committed config names, only once the tool selector matched, and \
                  only with the stdin this module assembled, so almost every tool result \
                  reaches none of it and the per-call budget is untouched. It stays a spawn \
                  rather than becoming a port because the censused program is the single \
                  authority on a grammar 19 other files share — a second implementation of it \
                  here would be the drift this whole migration exists to remove."
    )]
    let mut child = std::process::Command::new(root.join(&program.path))
        .args(&program.args)
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(payload.as_bytes()).ok()?;
    let finished = child.wait_with_output().ok()?;
    Some((
        finished.status.code()?,
        String::from_utf8_lossy(&finished.stdout).into_owned(),
    ))
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
    if !satisfied(declared, context.result, context.input) {
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

/// Refuse, at LOAD, every recorder that could not have written what it claims.
///
/// The refusals below are all of the same kind and it is the kind this repository
/// keeps choosing: a declaration naming something the tree does not carry is a
/// gate that runs, resolves nothing, and reports clean. A recorder is worse than
/// a rule that way, because it has no verdict at all — a column that silently
/// renders `-` forever looks exactly like a column that looked and could not see.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the recorder, the
/// column and the missing id.
pub fn validate(
    recorders: &[Declared],
    programs: &BTreeMap<String, Program>,
    patterns: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for recorder in recorders {
        if recorder.name.trim().is_empty() {
            return Err(crate::error::UsageError::raise(
                "a `[[recorder]]` row carries an empty `name`, so it names no record",
            ));
        }
        if !seen.insert(recorder.name.clone()) {
            return Err(crate::error::UsageError::raise(format!(
                "two `[[recorder]]` rows are named {:?}, so one would silently \
                 append to the other's record",
                recorder.name
            )));
        }
        if recorder.tool.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} selects on an empty `tool`, which matches nothing",
                recorder.name
            )));
        }
        if recorder.columns.is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} declares no columns, so it would append blank lines",
                recorder.name
            )));
        }
        for column in &recorder.columns {
            for value in [
                Some(&column.value),
                column.minus.as_ref(),
                column.without.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_value(&recorder.name, &column.name, value, programs, patterns)?;
            }
        }
    }
    Ok(())
}

/// Every id one expression names, checked against what the config declares.
fn validate_value(
    recorder: &str,
    column: &str,
    value: &Value,
    programs: &BTreeMap<String, Program>,
    patterns: &std::collections::BTreeSet<String>,
) -> Result<()> {
    match value {
        Value::Literal(_) | Value::Result(_) | Value::Input(_) | Value::Wrap { .. } => Ok(()),
        Value::Object(fields) => fields
            .values()
            .try_for_each(|value| validate_value(recorder, column, value, programs, patterns)),
        Value::Section {
            from,
            label,
            select,
        } => {
            for id in [label, select] {
                if !patterns.contains(id) {
                    return Err(crate::error::UsageError::raise(format!(
                        "recorder {recorder:?} column {column:?} narrows on pattern {id:?}, \
                         which no `[[pattern]]` row declares — an inline regex is refused here \
                         for the reason a policy module's is, so the id must exist"
                    )));
                }
            }
            validate_value(recorder, column, from, programs, patterns)
        }
        Value::Program {
            program,
            stdin,
            read,
        } => {
            if !programs.contains_key(program) {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {recorder:?} column {column:?} runs program {program:?}, \
                     which no `[program]` row declares"
                )));
            }
            if let Read::Status(map) = read {
                if map.is_empty() {
                    return Err(crate::error::UsageError::raise(format!(
                        "recorder {recorder:?} column {column:?} reads program {program:?}'s \
                         status through an empty table, so every status would record as \
                         could-not-look"
                    )));
                }
                for status in map.keys() {
                    if status.parse::<i32>().is_err() {
                        return Err(crate::error::UsageError::raise(format!(
                            "recorder {recorder:?} column {column:?} maps status {status:?}, \
                             which is not an exit code"
                        )));
                    }
                }
            }
            validate_value(recorder, column, stdin, programs, patterns)
        }
    }
}
