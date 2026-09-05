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
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Declared {
    /// What this row is called. Unique across the table, and never the file — a
    /// record is written by SEVERAL rows (one per tool, and one per create/groom
    /// path), so keying uniqueness on the file would make the natural
    /// declaration unwritable.
    pub name: String,
    /// The record this row appends to — the file, and the file the rule that
    /// reads it names.
    ///
    /// Deliberately many-to-one. The censused record carries a line per board
    /// write whatever tool made it, so the rows that write it differ in their
    /// selector and their columns while naming one destination.
    pub record: String,
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
    /// Input paths whose value must MATCH a declared pattern, by pattern id.
    ///
    /// **The selector a tool name cannot express.** [`Declared::tool`] narrows to
    /// a tool, which is enough while the tool's identity is the whole question —
    /// a board write is any `save_issue` at all. It is not enough for a general
    /// runner: every shell call arrives as one tool, so a row wanting *the
    /// command that fetched the pull request body* has a tool name that matches
    /// every command in the session and a result shape identical for all of them.
    ///
    /// The value is a `[[pattern]]` id rather than an inline regex, for the
    /// reason `rules/policy-modules.md` gives for a module: one concept,
    /// one spelling, refused at load rather than duplicated at leisure. An
    /// undeclared id fails the load and says which recorder named it.
    ///
    /// Reads the INPUT, never the result, and that is the safe direction here
    /// even though [`Value::Input`] is the forgeable half elsewhere: this decides
    /// only WHETHER to record, and the columns still take their values from what
    /// the far end returned. A caller who spoofs the command string buys a record
    /// of a call whose own result is what gets written down.
    ///
    /// A path that does not resolve to a scalar refuses the row, on the
    /// could-not-look rule the rest of this module keeps: a selector that cannot
    /// read its subject has not matched it.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub requires_input_matching: BTreeMap<String, String>,
    /// Write only when the record ALREADY carries a line whose column
    /// `column` equals this expression's value.
    ///
    /// **The narrow exception that keeps a remedy reachable.** A gate that
    /// refuses a subject recorded in a bad state has to tell the author how to
    /// clear it, and "fix the subject and re-run" only works if the fix is
    /// recorded too. But recording every later write would let a row this branch
    /// never filed be re-judged on its own say-so — so the exception is bounded
    /// to subjects this record already names, which is exactly the set this
    /// branch is answerable for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_recorded: Option<Recorded>,
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

/// A precondition on what the record already holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Recorded {
    /// Every column that must match, keyed by position from zero.
    ///
    /// **A map rather than one column, and the reason is measured.** The
    /// censused record carries a line per board write whatever KIND it was, so a
    /// precondition on the subject alone matches a comment line about that
    /// subject — and a comment is not this branch having filed the row. The
    /// retired shell anchored on the kind and the whole id field together; this
    /// is that anchor, generalised.
    pub matches: BTreeMap<usize, Value>,
}

/// One column of a record.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
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
    /// The branch this record is being written on (CLOUD-1280).
    ///
    /// **The record is already branch-keyed and this exposes what the writer
    /// holds** — [`crate::lib`]'s `write_records` resolves the branch to choose
    /// the record's own path and, until this variant, never handed it to an
    /// expression. So a column could name what the LEASE says and nothing it
    /// could compare that against.
    ///
    /// The measured need is one row of a port rather than a general convenience.
    /// `land-lock status` grades the lease against the CLONE (`mine`), which is
    /// the question a developer's checkout asks; `authorises` grades it against
    /// the BRANCH and admits one case `status` cannot — the successor a rival
    /// reserved behind the holder (CLOUD-369). A predicate without this variant
    /// therefore refuses a reserved successor that the bash it replaces allows,
    /// which is a fail-CLOSED deviation and exactly the laundering CLOUD-1269
    /// forbids: *"a port that quietly makes it fail closed has laundered a
    /// stop-the-world into a gate."*
    ///
    /// **Could-not-look is a real answer here and is spelled `None`**: a detached
    /// HEAD has no branch, which is a state rather than an error, and rendering
    /// some placeholder would let a comparison against it succeed by accident.
    ///
    /// Names nothing (non-negotiable rule 1): it yields whatever ref the clone is
    /// standing on, so a consumer's trunk name never reaches the crate.
    Branch,
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
    /// Every string the named iterating INPUT paths yield, space-joined.
    ///
    /// [`Value::Wrap`]'s plain sibling, and both are needed rather than one
    /// being a special case of the other. `Wrap` builds the OBJECT shape a
    /// program reads on stdin; this builds the TOKEN list a column operation
    /// compares against. Using `Wrap` for a `minus` compares against
    /// `{"id":"X"}` and removes nothing — measured, and silently, because a set
    /// difference that subtracts nothing looks exactly like one with nothing to
    /// subtract.
    ///
    /// A list rather than one path because the censused use unions three
    /// relation directions, and a union spelled as three columns would be three
    /// columns nobody wanted.
    Inputs(Vec<String>),
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
    /// same load-time refusal `rules/policy-modules.md` records for a
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
    ///
    /// The id field is `run` rather than `program`, which is not cosmetic: this
    /// enum is externally tagged, so the variant's own key is already `program`
    /// and a field of the same name nests one inside the other for a reader.
    Program {
        /// The program id, resolved through the consumer's `[program]` table.
        run: String,
        /// The expression whose rendered value is handed to the program on stdin.
        stdin: Box<Value>,
        /// What to read back.
        read: Read,
    },
    /// What a **compiled** authority said about another expression's value
    /// (CLOUD-1100).
    ///
    /// [`Value::Program`]'s in-process twin, and deliberately its twin rather
    /// than its replacement: a `[program]` row names a path the CONSUMER owns, an
    /// authority names a predicate the CRATE owns. Switching a column from one to
    /// the other buys the same verdict without a spawn, which is what lets a
    /// grammar the crate already parses stop being resolved by executing a shell
    /// program on every board write.
    ///
    /// **[`Read`] is reused unchanged, and that is the whole compatibility
    /// story.** The authority answers in the spawned program's own status
    /// contract (see [`crate::ready::adjudicate`], which documents the inversion
    /// CLOUD-909 records), so a column switching `program` for `authority` keeps
    /// its `read` table byte-for-byte and keeps recording the same tokens.
    Authority {
        /// Which compiled authority decides.
        ask: Ask,
        /// The expression whose value the authority judges. Handed over as JSON
        /// rather than as text: nothing is being written to a pipe, so the
        /// serialize-and-reparse round trip a spawn needs would only be a second
        /// place for the shape to change.
        stdin: Box<Value>,
        /// What to read back.
        read: Read,
    },
}

/// A compiled authority a recorder column may ask.
///
/// **Closed, and a name rather than a path**, which is what keeps rule 1 intact:
/// this enum's one variant says *the Definition-of-Ready grammar* and nothing
/// here names a tracker, a tool or a board. [`crate::mint::Authority`] is its
/// twin on the template side and the two resolve the same names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub enum Ask {
    /// [`crate::ready`] — the Ready-block grammar over a tracker payload.
    Ready,
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
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Program {
    /// The path, repo-relative. Resolved against the repository root rather than
    /// the cwd for [`crate::lib`]'s measured reason: a hook inherits the cwd of
    /// the tool call, which is not required to be inside this project.
    pub path: String,
    /// Arguments, before stdin is written.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
}

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
#[must_use]
pub fn outcome(declared: &Declared, context: &Context<'_>) -> Outcome {
    let selected = declared
        .refused_when_input
        .iter()
        .all(|path| scalar(context.input, path).is_none())
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
        validate_shape(recorder, &mut seen, patterns)?;
        if let Some(recorded) = &recorder.requires_recorded {
            for value in recorded.matches.values() {
                validate_value(
                    &recorder.name,
                    "requires-recorded",
                    value,
                    programs,
                    patterns,
                )?;
            }
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

/// The shape refusals, split out of [`validate`] when it hit its own line
/// ceiling. The seam is the one the function already had: everything here is a
/// property of the ROW — its name, its selectors, its column count — and
/// everything left behind walks the expressions inside a column.
fn validate_shape(
    recorder: &Declared,
    seen: &mut std::collections::BTreeSet<String>,
    patterns: &std::collections::BTreeSet<String>,
) -> Result<()> {
    if recorder.name.trim().is_empty() {
        return Err(crate::error::UsageError::raise(
            "a `[[recorder]]` row carries an empty `name`, so nothing can point at it",
        ));
    }
    if recorder.record.trim().is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} names no `record`, so it would write nowhere",
            recorder.name
        )));
    }
    if !seen.insert(recorder.name.clone()) {
        return Err(crate::error::UsageError::raise(format!(
            "two `[[recorder]]` rows are named {:?}, so a finding could not say \
             which one wrote a line",
            recorder.name
        )));
    }
    if recorder.tool.trim().is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} selects on an empty `tool`, which matches nothing",
            recorder.name
        )));
    }
    // A SELECTOR IS NOT A GLOB, and a row that thinks it is fails SILENTLY.
    //
    // `rules::selects_tool_name` matches the whole name or its final
    // `__`-delimited segment (CLOUD-178, so a connector renamed over its
    // lifetime still matches). A `*save_issue` written by habit from a shell
    // `case` pattern therefore matches nothing at all — and a recorder that
    // never fires is byte-identical, on every surface, to a tool nobody
    // called. Measured here: the whole table was dead and only the cases
    // asserting a row WAS written could see it, because the ones asserting
    // none passed vacuously.
    //
    // Refused at load for that asymmetry: the failure has no loud direction
    // at runtime, so the only place it can be caught is before the run.
    if let Some(found) = recorder
        .tool
        .find(['*', '?', '['])
        .and_then(|at| recorder.tool.get(at..=at))
    {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} selects on tool {:?}, which carries {found:?} — a tool \
             selector is matched whole or by its final `__`-delimited segment, \
             never as a glob, so this row would match nothing and record silently",
            recorder.name, recorder.tool
        )));
    }
    for (path, pattern) in &recorder.requires_input_matching {
        if path.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} matches on an empty input path, which reads nothing \
                 and so never selects",
                recorder.name
            )));
        }
        if !patterns.contains(pattern) {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} selects on input {path:?} matching pattern {pattern:?}, \
                 which no `[[pattern]]` row declares — the row would never fire and \
                 a recorder that never fires is indistinguishable from a tool nobody \
                 called",
                recorder.name
            )));
        }
    }
    if recorder.columns.is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} declares no columns, so it would append blank lines",
            recorder.name
        )));
    }
    if let Some(recorded) = &recorder.requires_recorded {
        if recorded.matches.is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} gates on an empty `requires-recorded`, which every \
                 existing line satisfies — a precondition matching anything is not one",
                recorder.name
            )));
        }
        for column in recorded.matches.keys() {
            if *column >= recorder.columns.len() {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {:?} gates on column {column} of an existing line, but \
                     it declares only {} column(s) — the comparison could never hold",
                    recorder.name,
                    recorder.columns.len()
                )));
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
        Value::Literal(_)
        | Value::Branch
        | Value::Result(_)
        | Value::Input(_)
        | Value::Inputs(_)
        | Value::Wrap { .. } => Ok(()),
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
        Value::Program { run, stdin, read } => {
            if !programs.contains_key(run) {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {recorder:?} column {column:?} runs program {run:?}, \
                     which no `[program]` row declares"
                )));
            }
            validate_status_table(recorder, column, run, read)?;
            validate_value(recorder, column, stdin, programs, patterns)
        }
        // NO ID TO RESOLVE, and that is the point of the variant rather than a
        // gap in this function: `ask` is a closed enum, so serde has already
        // refused an authority no build carries. What still needs checking is the
        // status table, which is the consumer's either way.
        Value::Authority { ask, stdin, read } => {
            validate_status_table(recorder, column, &format!("{ask:?}").to_lowercase(), read)?;
            validate_value(recorder, column, stdin, programs, patterns)
        }
    }
}

/// A `read = { status = … }` table that can actually decide something.
///
/// Shared by the spawning and the compiled arms: an empty table records
/// could-not-look for every status, and a key that is not an exit code can never
/// match one.
fn validate_status_table(recorder: &str, column: &str, source: &str, read: &Read) -> Result<()> {
    let Read::Status(map) = read else {
        return Ok(());
    };
    if map.is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {recorder:?} column {column:?} reads {source:?}'s status through an empty \
             table, so every status would record as could-not-look"
        )));
    }
    for status in map.keys() {
        if status.parse::<i32>().is_err() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {recorder:?} column {column:?} maps status {status:?}, which is not an \
                 exit code"
            )));
        }
    }
    Ok(())
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
                std::fs::read_to_string(&path).unwrap_or_default(),
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
    let branch = branch.replace('/', "-");
    let name = match claim {
        Some(claim) => format!("recorder-blocked.{branch}.{claim}"),
        None => format!("recorder-blocked.{branch}"),
    };
    git_dir.join("batten-receipts").join(name)
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
/// `pr-closes` record still named a merged PR's keys and `filed-over-own-diff`'s
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
    let branch = branch.replace('/', "-");
    let name = match claim {
        Some(claim) => format!("{record}.{branch}.{claim}"),
        None => format!("{record}.{branch}"),
    };
    git_dir.join("batten-receipts").join(name)
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
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .ok()?;
    writeln!(file, "{line}").ok()
}

#[cfg(test)]
#[expect(
    clippy::expect_used,
    reason = "a test literal that does not compile is a broken test, not a reachable path"
)]
mod outcome_tests {
    use super::*;

    fn declared(requires: &[&str], matching: &[(&str, &str)]) -> Declared {
        Declared {
            name: "r".to_owned(),
            record: "r".to_owned(),
            tool: "Bash".to_owned(),
            key: RecordKey::Branch,
            requires: requires.iter().map(|path| (*path).to_owned()).collect(),
            refused_when_input: Vec::new(),
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
        };
        assert_eq!(outcome(&row, &applies), Outcome::Applies);
        assert!(satisfied(&row, &applies));
        assert!(!satisfied(&row, &blocked));
    }
}
