//! The step cache (CLOUD-424), retiring `[tasks.step-receipt]` (CLOUD-843).
//!
//! **A per-step receipt keyed by what the step actually reads.** The whole-gate
//! receipt is keyed to a SHA, so a rebase that leaves the tree byte-identical
//! re-runs every step; this keys each step on its declared inputs instead — the
//! INDEX blob ids under the step's pathspecs, the stdout of each declared tool
//! argv (a version, or the declaration of the step's own command), every `--arg`
//! in order, the declaring row itself, and, under `step run`, the command.
//!
//! NOT test-impact selection, which this repository refused and still refuses:
//! nothing infers what a change "could" affect. The claim is the one a receipt
//! already makes — same inputs, command and tools, same verdict — applied per
//! step.
//!
//! # The step table is the consumer's (non-negotiable rule 1)
//!
//! Which steps exist, what each reads and which tools it trusts are facts about a
//! repository, so they are `[[step]]` rows in its committed `batten.toml`, read
//! from the committed authority alone (`crate::resolve::committed`), and from
//! the authority of THE TREE BEING KEYED: the working directory's own
//! `batten.toml`, never the `--config-from` ref or `--config-in` directory a
//! global flag (or its `BATTEN_CONFIG_*` env form) would point the rest of the
//! run at. Those flags move where a policy is read from while the subject stays
//! put, and for this table the policy IS a claim about the subject: a row read
//! from anywhere else could declare a narrower `inputs` and key a receipt to
//! files the step never read. So the verb takes no source override at all, and
//! the retired task's `BATTEN_STEP_SPECS` and `BATTEN_STEP_TOOLS` overrides —
//! the same door — did not survive the port either. What remains is the tree's
//! own committed row, and the row itself is key material: narrowing its
//! `inputs` or `tools` is a miss, so a receipt minted under one declaration
//! never answers under another. The row's type and its load-time validator are
//! [`crate::step_table`], a leaf, so the loader that refuses a bad row never
//! reaches this module and, through it, `resolve`.
//!
//! # What a row can key, and what it cannot
//!
//! The key reads three things: index entries under pathspecs, tool stdout, and
//! arguments. A step whose verdict reads ANYTHING ELSE — the record and capture
//! stores under the git directory, a remote ref, the clock, the network — has
//! inputs no row can name, and a receipt over it would answer `hit` after that
//! state moved with no tracked change. Such a step is not a candidate for this
//! cache and must not be declared; `--arg` is the one door for a value outside
//! the tree, and only where the caller can compute the whole of it.
//!
//! ONE TOOL LINE IS THE ENGINE'S OWN, AND ANSWERED IN-PROCESS (step 17):
//! [`INPUTS_DIGEST`], the digest of the out-of-tree state `enforce --half tree`
//! reads. Spawned, it cost a `cargo run` build check and a policy load on every
//! lap, for a value this binary computes directly. A tool line rather than a
//! new row key, because the released engine reads this authority too and a
//! row it does not know would refuse the whole file; an engine without the
//! in-process answer spawns the line, and one that cannot answer it has no key
//! and runs the step.
//!
//! # Fail closed, everywhere
//!
//! A key that cannot be computed — an authority that will not load, an
//! undeclared step, a tool that will not answer, a pathspec resolving to
//! nothing, a worktree disagreeing with the index over the set, an untracked
//! file inside it — is "run the step", never "assume unchanged" and never an
//! error in the step's place. An unreadable store reads as a miss and refuses a
//! record.
//!
//! # Check and record are a pair
//!
//! `check` files the key it computed under the pending family; `record`
//! recomputes and refuses on any mismatch, so a tree that changed while the step
//! ran can never mint a receipt for bytes it never judged. **A hit leaves the
//! pending slot alone**: one slot per step, and a runner may run a step twice at
//! once, so a hit that blanked it would strand the concurrent twin's `record`.
//! A stale pending key cannot mint a false receipt — `record` recomputes.
//!
//! `run` is the pair composed so a caller writes no shell around it: check, run
//! the command on a miss through [`crate::exec::run`] (the child's code is the
//! verb's, passed through unchanged), and record the verdict. A record that
//! refuses after a run is an economy lost, never the step's verdict.
//!
//! # A failure is a verdict too (CLOUD-2253)
//!
//! A receipt written only on a pass left a failed step with no record of its
//! inputs, so a lap on a known-red tree re-ran the whole fan to say red again
//! (measured on #1276: three failures known, a held lap still ran ~35 minutes).
//! So `run` records a FAILURE receipt under exactly the key a pass would use,
//! carrying the child's code and a pointer to its stored log, and a later `run`
//! at that key answers `red` with that code without running anything. A pass
//! at the key replaces it, and [`BYPASS`] still forces a run.
//!
//! Red is reused only where the change could have caused it: a journaled run
//! whose every failing case is flaky-suspect (its sealed reach misses the
//! change, CLOUD-2786) is recorded as such and re-runs. A code past 125 is a
//! signal or a shell that could not start the command, never a verdict over
//! the inputs, and is not recorded. The failure's first line keeps the key off
//! its last field, so an engine released before this reads it as no receipt
//! and runs the step — never as a pass.
//!
//! # Local only
//!
//! Under `CI` (or `BATTEN_STEP_RECEIPT_BYPASS`) the cache is off: `check` answers
//! `miss` and `record` writes nothing, because CI's job is to confirm
//! independently.
//!
//! # Output is a pointer (non-negotiable rule 4)
//!
//! `hit`/`miss`, the step's own declared name and twelve characters of the key.
//! Never an input's bytes, never a tool's output. A miss is an answer in words
//! at exit 0 (CLOUD-498): it is not a failure, and a caller that branched on the
//! code alone would read "run the step" as a broken gate.
//!
//! **It spawns nothing of its own.** Tool argvs go through
//! `crate::exec::piped_argv` and the step's command through
//! [`crate::exec::run`] — the placed boundary — so the spawn inventory does not
//! grow by the cache.
//!
//! # What the layering table holds here, and what it does not
//!
//! `step -> rules` and `step -> hook` are forbidden as DIRECT edges: this
//! module names nothing that decides. It is not a transitive guarantee. The
//! index read goes through `crate::git::index_facts`, and `git` reaches `rules`
//! for its tree walker and glob selector, so `rules` is two hops out. What
//! crosses that hop is a file list, never a verdict: no `Finding` is minted on
//! this path and no rule is evaluated.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use sha2::Digest as _;

use crate::exit::ExitCode;
use crate::resolve::Overrides;
use crate::step_table::Step;

/// The grouped family a passed step's receipts live in: one record per (step,
/// key), so a return to a tree the step already judged is a hit (CLOUD-2784).
pub const RECEIPTS: &str = "step-receipts";

/// The family that held ONE receipt per step before CLOUD-2784. A step's first
/// write under [`RECEIPTS`] removes its record here, so none is left unread.
const SUPERSEDED_RECEIPTS: &str = "steps";

/// How many receipts a step keeps. Past it, the oldest go first ([`evict`]).
const KEPT_RECEIPTS: usize = 32;

/// The keyed family `check` files the key under that a `record` must match.
pub const PENDING: &str = "step-pending";

/// The variable that switches the cache off locally, so a measurement can see
/// the uncached cost.
pub const BYPASS: &str = "BATTEN_STEP_RECEIPT_BYPASS";

/// The variable a supervising task exports its registry pid in (CLOUD-425).
pub(crate) const TASK_PID: &str = "BATTEN_TASK_PID";

/// How much of the key a line shows. A pointer, never the whole digest.
const SHOWN: usize = 12;

// The cache's mutation rows, carried from the retired task's six and widened by
// the three the composed `run` arm adds. Each breaks one clause a receipt's
// soundness rests on, and each is caught by the compiled-binary case it names.
// And the three the review added: the row as key material, the table read from
// the keyed tree alone, and no key running the step rather than skipping it.

/// What a check found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Answer {
    /// The cache is off here (CI or the bypass).
    Off,
    /// No key could be computed, so the step runs and nothing is recorded.
    NoKey,
    /// A receipt covers this exact key.
    Hit(String),
    /// A key, and no receipt for it.
    Miss(String),
    /// A failure receipt covers this exact key (CLOUD-2253): not re-run.
    Red(String, Failure),
    /// A failure receipt covers this key, but every failing case was a flaky
    /// suspect: run again, like a miss.
    Suspect(String),
}

/// What a failure receipt recorded: the child's code and its pointers.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Failure {
    /// The code the failed run exited with.
    code: i32,
    /// The stored streams' capture handles, space-separated.
    log: Option<String>,
    /// The failing cases and the command that confirms a fix, as said.
    cases: Option<String>,
}

impl Answer {
    /// The one line a check says, in words (CLOUD-498).
    fn line(&self, step: &str) -> String {
        match self {
            Answer::Off => {
                String::from("miss — the cache is off here (CI or bypass); running the step")
            }
            Answer::NoKey => format!(
                "miss — {step}: no key (dirty, unreadable, or undeclared inputs); running the step"
            ),
            Answer::Hit(key) => format!(
                "hit {} — {step}: this receipt already covers these exact inputs, command and \
                 tools; not re-deriving",
                shown(key)
            ),
            Answer::Miss(key) => {
                format!(
                    "miss — {step}: no receipt for {}; running the step",
                    shown(key)
                )
            }
            Answer::Red(key, failure) => format!(
                "red {} — {step}: a failure receipt (exit {}) already covers these exact \
                 inputs, command and tools; not re-running",
                shown(key),
                failure.code
            ),
            Answer::Suspect(key) => format!(
                "miss — {step}: the failure recorded for {} is flaky-suspect; running the step",
                shown(key)
            ),
        }
    }

    /// The key a run of this answer records under, where it may record.
    fn recording(&self) -> Option<&str> {
        match self {
            Answer::Miss(key) | Answer::Suspect(key) => Some(key),
            _ => None,
        }
    }

    /// Whether the step may be answered from its receipt.
    #[cfg(test)]
    const fn is_hit(&self) -> bool {
        matches!(self, Answer::Hit(_))
    }
}

/// The first [`SHOWN`] characters of a key.
fn shown(key: &str) -> &str {
    key.get(..SHOWN).unwrap_or(key)
}

/// Whether the cache is switched off here: under a forge runner's `$CI`, or
/// [`BYPASS`]. Also the rule the mutation pass record follows
/// (`mutate::ChangePass`), so every local-only answer is off in the same place.
pub(crate) fn bypassed() -> bool {
    under_ci() || set(BYPASS)
}

/// Whether this is a forge runner's `$CI`: the half of [`bypassed`] under which
/// no journal answers either (CLOUD-2850). [`BYPASS`] switches off the receipt
/// alone and keeps the journals, which a fixture needs to drive them.
pub(crate) fn under_ci() -> bool {
    set("CI")
}

/// Whether `name` is set to something.
fn set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

/// Say which step a supervising task is on (CLOUD-425). Best-effort:
/// bookkeeping never changes a verdict, and a pid nothing registered is a no-op.
fn announce(step: &str) {
    push_to_supervisor(crate::task::Signal::Phase, step);
}

/// Say that a long step moved forward without changing which step it is
/// (CLOUD-2369's other half): the `Sig` field, which the self-stall arm reads
/// beside the phase. MEASURED ON #1276: the schema sweep judged 3,723 mutants
/// in 8,193 s inside the one `mutant:changed` step, past the 240-beat bound,
/// and the lap was cancelled as stalled while it was still advancing.
pub(crate) fn advanced(what: &str) {
    push_to_supervisor(crate::task::Signal::Sig, what);
}

/// One push to the record of the task exported in [`TASK_PID`]. Best-effort,
/// like every bookkeeping write: no supervisor, or no repository, is a no-op.
fn push_to_supervisor(signal: crate::task::Signal, value: &str) {
    let Some(pid) = std::env::var(TASK_PID).ok().filter(|pid| !pid.is_empty()) else {
        return;
    };
    let Ok(git_dir) = crate::git::git_dir(Path::new(".")) else {
        return;
    };
    crate::task::push(&git_dir, &pid, signal, value, crate::clock::now_unix());
}

/// The row the keyed tree's own committed `batten.toml` declares for `step`.
///
/// `None` for an undeclared step AND for an authority that will not load: both
/// are "no key", which runs the step (fail closed) rather than standing an error
/// in the step's verdict. No source override reaches this read — see the module
/// doc — so the default [`Overrides`] is passed deliberately, not for want of
/// the run's own.
fn declared(step: &str) -> Option<Step> {
    let config = crate::resolve::committed(Path::new("."), &Overrides::default()).ok()?;
    config.steps.into_iter().find(|row| row.id == step)
}

/// The part of a row a key hashes: the three fields a row had before it could
/// schedule (CLOUD-2785), serialized exactly as the whole row then was.
#[derive(serde::Serialize)]
struct KeyRow<'a> {
    id: &'a str,
    inputs: &'a [String],
    tools: &'a [Vec<String>],
}

/// The key's `row` line: ONLY `id`, `inputs` and `tools` (CLOUD-2785), in the
/// order and spelling the whole row serialized to before it could schedule, so
/// no field added since moves a key. `None` for a schedule-only node.
fn row_line(row: &Step) -> Option<String> {
    let (Some(inputs), Some(tools)) = (&row.inputs, &row.tools) else {
        return None;
    };
    let projected = KeyRow {
        id: &row.id,
        inputs,
        tools,
    };
    Some(format!("row {}", serde_json::to_string(&projected).ok()?))
}

/// Everything the key hashes, or `None` where any part cannot be read.
///
/// Each component is a line of its own and every free-form value is JSON-quoted,
/// so no tool's output can impersonate the lines that follow it.
fn material(
    root: &Path,
    row: &Step,
    args: &[String],
    command: Option<&[String]>,
) -> Option<String> {
    // A SCHEDULE-ONLY NODE KEYS NOTHING (CLOUD-2785): it declares neither list.
    let (Some(inputs), Some(tools)) = (&row.inputs, &row.tools) else {
        return None;
    };
    let mut lines: Vec<String> = vec![format!("step {}", serde_json::to_string(&row.id).ok()?)];
    // The declaration itself: a receipt earned under one `inputs`/`tools` set
    // never answers under a narrower one.
    lines.push(row_line(row)?);
    lines.extend(args.iter().map(|arg| format!("arg {}", quoted(arg))));
    if let Some(command) = command {
        lines.push(format!("command {}", serde_json::to_string(command).ok()?));
    }
    // THE DECLARED ENVIRONMENT (CLOUD-2786) is a `batten step env` entry of
    // `tools`, answered in-process by `tool_said`: a row without one keys byte
    // for byte as before, and one that will not parse is no key.
    for tool in tools {
        let (code, said) = tool_said(root, tool)?;
        let said = said.trim();
        if code != 0 || said.is_empty() {
            return None;
        }
        lines.push(format!(
            "tool {} {}",
            serde_json::to_string(tool).ok()?,
            quoted(said)
        ));
    }
    let facts = crate::git::index_facts(root, inputs).ok()?;
    let mut entries: BTreeMap<(String, u32), String> = BTreeMap::new();
    for fact in facts.values() {
        // THE INDEX IS WHAT THE KEY HASHES, so the worktree must agree with it
        // over the set: a receipt over index bytes the run never saw is the one
        // thing this cache may not mint.
        let clean = fact.diverged.is_empty() && fact.untracked.is_empty();
        if !clean {
            return None;
        }
        for entry in &fact.entries {
            entries.insert(
                (entry.path.clone(), entry.stage),
                format!(
                    "{} {} {}\t{}",
                    entry.mode, entry.oid, entry.stage, entry.path
                ),
            );
        }
    }
    // A set that resolves to nothing keys nothing, and a receipt over nothing
    // would answer for every tree.
    if entries.is_empty() {
        return None;
    }
    lines.push(String::from("inputs"));
    lines.extend(entries.into_values());
    Some(lines.join("\n"))
}

/// The tool line the cache answers in-process rather than spawning: the
/// digest `enforce --half tree --inputs-digest` prints, by the same function
/// ([`tree_inputs_digest_in`]).
pub const INPUTS_DIGEST: [&str; 5] = ["batten", "enforce", "--half", "tree", "--inputs-digest"];

/// What `tool` says run in `root`, as its exit code and stdout: answered
/// in-process for [`INPUTS_DIGEST`], a [`BASE`] line and an
/// [`ENV`](crate::mutate::resume::ENV) line (one that cannot be answered is a
/// non-zero code, so no key), spawned through the placed boundary for every
/// other line. `None` where it could not be spawned.
fn tool_said(root: &Path, tool: &[String]) -> Option<(i32, String)> {
    let answered =
        |said: Option<String>| Some(said.map_or_else(|| (1, String::new()), |said| (0, said)));
    if tool.iter().map(String::as_str).eq(INPUTS_DIGEST) {
        return answered(tree_inputs_digest_in(root).ok());
    }
    if let Some(words) = after(tool, &BASE) {
        let var = |name: &str| std::env::var(name).ok();
        return answered(base_ask(words).and_then(|ask| base_said(root, &ask, &var)));
    }
    if let Some(words) = after(tool, &crate::mutate::resume::ENV) {
        return answered(
            crate::mutate::resume::env_ask(words)
                .and_then(|declared| env_lines(&declared, std::env::vars_os()))
                .map(|lines| lines.join("\n")),
        );
    }
    crate::exec::piped_argv(root, tool, "", crate::exec::Diagnostics::Drop, &[])
}

/// The words of `tool` after `head`, where it begins with `head`.
fn after<'a>(tool: &'a [String], head: &[&str]) -> Option<&'a [String]> {
    tool.get(..head.len())
        .filter(|start| start.iter().map(String::as_str).eq(head.iter().copied()))
        .and_then(|_| tool.get(head.len()..))
}

/// `step env` (CLOUD-2786): print the sorted `env "NAME=value"` and
/// `env "PATTERN" none` lines the declaration keys in this process's
/// environment, the lines the step cache answers the row's tool line with;
/// exit 0. 1 for a declaration that names no pattern or a malformed name, 3
/// for a keyed value that is not Unicode.
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_env(
    exclude: &[String],
    patterns: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let Some(declared) = crate::mutate::resume::declare(patterns.to_vec(), exclude.to_vec()) else {
        writeln!(
            err,
            "step env: at least one NAME or PREFIX* pattern after `--`, and --exclude takes a NAME"
        )?;
        return Ok(ExitCode::Usage);
    };
    let Some(lines) = env_lines(&declared, std::env::vars_os()) else {
        writeln!(err, "step env: a keyed variable's value is not Unicode")?;
        return Ok(ExitCode::Internal);
    };
    for line in lines {
        writeln!(out, "{line}")?;
    }
    Ok(ExitCode::Success)
}

/// The tool line prefix the cache answers in-process for a two-tree step's
/// base half (CLOUD-2787): `batten step base --ref <ref> [--ref-env <VAR>] --
/// <path>...`, by the same function [`run_base`] prints with ([`base_said`]).
pub const BASE: [&str; 3] = ["batten", "step", "base"];

/// What a `step base` line asks: the ref, the variable that overrides it when
/// set and non-empty, and the pathspecs whose content ids are its answer.
#[derive(Debug, Clone, PartialEq, Eq)]
struct BaseAsk {
    reference: String,
    ref_env: Option<String>,
    paths: Vec<String>,
}

/// The [`BaseAsk`] a tool line's words after [`BASE`] spell, or `None` for any
/// other shape — which keys nothing, so the step runs. Only the canonical
/// spelling is read: `--ref` and `--ref-env` as separate tokens, then `--`.
fn base_ask(words: &[String]) -> Option<BaseAsk> {
    let (mut reference, mut ref_env) = (None, None);
    let mut rest = words.iter();
    loop {
        match rest.next()?.as_str() {
            "--ref" => reference = Some(rest.next()?.clone()),
            "--ref-env" => ref_env = Some(rest.next()?.clone()),
            "--" => break,
            _ => return None,
        }
    }
    let paths: Vec<String> = rest.cloned().collect();
    let reference = reference.filter(|named: &String| !named.is_empty())?;
    (!paths.is_empty()).then_some(BaseAsk {
        reference,
        ref_env,
        paths,
    })
}

/// The ref `ask` compares against: `ref_env`'s value when that variable is set
/// and non-empty under `var`, else the declared ref.
fn base_ref(ask: &BaseAsk, var: &dyn Fn(&str) -> Option<String>) -> String {
    ask.ref_env
        .as_deref()
        .and_then(var)
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| ask.reference.clone())
}

/// The base lines for `ask`: one `base <path> <id>` per pathspec, read at the
/// MERGE BASE of `HEAD` and [`base_ref`], never the ref's tip — the revision
/// `test replay` and `perf-gate` actually compare against. `None` where the
/// ref or the merge base cannot be resolved: no key, so the step runs.
///
/// NO COMMIT ID ENTERS THE ANSWER: a trunk that gains a commit touching none of
/// the paths moves the merge base after a rebase, never these lines.
fn base_said(root: &Path, ask: &BaseAsk, var: &dyn Fn(&str) -> Option<String>) -> Option<String> {
    let fork = crate::git::merge_base(root, &base_ref(ask, var)).ok()??;
    base_lines_at(root, &fork, &ask.paths)
}

/// One `base <path> <id>` line per path, `<id>` the object `commit:<path>`
/// names (`.` naming the commit's root tree), `absent` where the path is
/// missing there. `None` only when the repository cannot be read.
pub(crate) fn base_lines_at(root: &Path, commit: &str, paths: &[String]) -> Option<String> {
    let mut lines = Vec::with_capacity(paths.len());
    for path in paths {
        let trimmed = path.trim_end_matches('/');
        let rev = if trimmed.is_empty() || trimmed == "." {
            format!("{commit}^{{tree}}")
        } else {
            format!("{commit}:{trimmed}")
        };
        let id = crate::git::resolve_ref(root, &rev)
            .ok()?
            .unwrap_or_else(|| String::from("absent"));
        lines.push(format!("base {path} {id}"));
    }
    Some(lines.join("\n"))
}

/// `step base` (CLOUD-2787): print the base lines for `reference` (or
/// `ref_env`'s value when set and non-empty) over `paths`, exit 0; 3 when the
/// ref or its merge base with `HEAD` does not resolve, 1 for an empty ref.
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_base(
    reference: &str,
    ref_env: Option<&str>,
    paths: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    if reference.is_empty() || paths.is_empty() {
        writeln!(err, "step base: --ref and at least one path are required")?;
        return Ok(ExitCode::Usage);
    }
    let ask = BaseAsk {
        reference: reference.to_owned(),
        ref_env: ref_env.map(str::to_owned),
        paths: paths.to_vec(),
    };
    let var = |name: &str| std::env::var(name).ok();
    let Some(lines) = base_said(Path::new("."), &ask, &var) else {
        writeln!(
            err,
            "step base: {} or its merge base with HEAD does not resolve",
            base_ref(&ask, &var)
        )?;
        return Ok(ExitCode::Internal);
    };
    writeln!(out, "{lines}")?;
    Ok(ExitCode::Success)
}

/// A free-form value as one JSON string, or the value itself where it cannot be
/// encoded (a `str` always can).
fn quoted(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| value.to_owned())
}

/// The SHA-256 of the material, as lowercase hex.
fn key_of(material: &str) -> String {
    use std::fmt::Write as _;
    let digest = sha2::Sha256::digest(material.as_bytes());
    let mut hex = String::with_capacity(64);
    for byte in &digest {
        // `write!` to a `String` is infallible; discarded rather than unwrapped
        // because the library lints forbid an unwrap here.
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The key a stored value carries: the last field of its first line.
///
/// A receipt is `<timestamp> <key>` and a pending value is `<key>`, so one
/// reading serves both. A blank value reads as none.
fn stored_key(value: &str) -> Option<String> {
    value
        .lines()
        .next()?
        .split_whitespace()
        .last()
        .map(str::to_owned)
}

/// The key one family holds for `step`, or `None` — absent, unreadable and
/// malformed all read as nothing, which every caller treats as "run".
fn read_key(git_dir: Option<&Path>, family: &str, step: &str) -> Option<String> {
    stored_key(&crate::record::keyed_read(git_dir?, family, step)?)
}

/// Decide hit or miss, filing the pending key on a miss.
///
/// Infallible by construction: every way a key can fail to form — an authority
/// that will not load included — is [`Answer::NoKey`], so no caller can be made
/// to report an error where the step's own verdict belongs.
fn check(step: &str, args: &[String], command: Option<&[String]>) -> Answer {
    announce(step);
    if bypassed() {
        return Answer::Off;
    }
    let row = declared(step);
    let git_dir = crate::git::git_dir(Path::new(".")).ok();
    let key = row
        .as_ref()
        .and_then(|row| material(Path::new("."), row, args, command))
        .map(|material| key_of(&material));
    let Some(key) = key else {
        // Blank the pending slot so a later `record` has nothing to match.
        // Best-effort: a store that will not take it leaves a `record` that
        // recomputes and refuses anyway.
        if let Some(git_dir) = &git_dir {
            let _ = crate::record::keyed_write(git_dir, PENDING, step, "\n");
        }
        return Answer::NoKey;
    };
    // THE RECEIPT FOR THIS KEY, among the step's many (CLOUD-2784): one record
    // per key it passed under, so the lookup is by the fresh key itself, and its
    // last field still has to equal that key for a hit.
    let body = git_dir
        .as_deref()
        .and_then(|git_dir| crate::record::keyed_group_read(git_dir, RECEIPTS, step, &key));
    let stored = body.as_deref().and_then(stored_key);
    if stored.as_deref() == Some(key.as_str()) {
        return Answer::Hit(key);
    }
    // A FAILURE AT THIS KEY (CLOUD-2253), read only where `run` wrote it: a
    // check's key carries no command, so it never meets one.
    let failed = command
        .and(body.as_deref())
        .and_then(|body| failure_of(body, &key));
    if let Some((failure, false)) = failed {
        return Answer::Red(key, failure);
    }
    let suspect = failed.is_some();
    // The pending key is what a later `record` must match. A store that will not
    // take it costs the economy, never the verdict: `record` then refuses.
    if let Some(git_dir) = &git_dir {
        let _ = crate::record::keyed_write(git_dir, PENDING, step, &format!("{key}\n"));
    }
    if suspect {
        return Answer::Suspect(key);
    }
    Answer::Miss(key)
}

/// The failure a receipt body records for `key`, and whether it was
/// flaky-suspect: a first line `<stamp> <n>ms <key> exit <code>[ flaky]`, then
/// optional `log <handles>` and `cases <said>` lines. `None` for a pass, or for
/// anything malformed, which every caller treats as "run".
fn failure_of(body: &str, key: &str) -> Option<(Failure, bool)> {
    let mut lines = body.lines();
    let first: Vec<&str> = lines.next()?.split_whitespace().collect();
    let at = first.iter().position(|field| *field == key)?;
    let (word, code) = (first.get(at + 1)?, first.get(at + 2)?);
    if *word != "exit" {
        return None;
    }
    let code = code.parse::<i32>().ok().filter(|code| *code != 0)?;
    let flaky = match first.get(at + 3..)? {
        [] => false,
        ["flaky"] => true,
        _ => return None,
    };
    let mut failure = Failure {
        code,
        log: None,
        cases: None,
    };
    for line in lines {
        if let Some(log) = line.strip_prefix("log ") {
            failure.log = Some(log.to_owned());
        } else if let Some(cases) = line.strip_prefix("cases ") {
            failure.cases = Some(cases.to_owned());
        }
    }
    Some((failure, flaky))
}

/// Whether a failed run's code is a verdict over its inputs: a child's own
/// code, never a signal (`128 + N`) or a shell that could not run it.
const fn recordable_failure(code: i32) -> bool {
    1 <= code && code <= 125
}

/// Record the step's receipt, refusing when the key moved since the check.
///
/// `said` takes the one line of success; a refusal goes to `err`.
fn record(
    step: &str,
    args: &[String],
    command: Option<&[String]>,
    elapsed: Option<std::time::Duration>,
    said: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    record_as(step, args, command, elapsed, None, said, err)
}

/// [`record`], of a failure when `failed` names one (CLOUD-2253): the same key,
/// the same refusals, the same slot, so a pass and a failure replace each other.
fn record_as(
    step: &str,
    args: &[String],
    command: Option<&[String]>,
    elapsed: Option<std::time::Duration>,
    failed: Option<(&Failure, bool)>,
    said: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    if bypassed() {
        return Ok(ExitCode::Success);
    }
    let git_dir = crate::git::git_dir(Path::new(".")).ok();
    let Some(expected) = read_key(git_dir.as_deref(), PENDING, step) else {
        writeln!(
            err,
            "step record: {step} — no pending key from a paired check; not recording"
        )?;
        return Ok(ExitCode::Violation);
    };
    // An authority that will not load is no key, and no key never matches: the
    // record refuses below rather than erroring in a passed step's place.
    let key = declared(step)
        .as_ref()
        .and_then(|row| material(Path::new("."), row, args, command))
        .map(|material| key_of(&material));
    if key.as_deref() != Some(expected.as_str()) {
        writeln!(
            err,
            "step record: {step} — the key moved while the step ran (changed inputs, or \
             a row or authority that no longer reads); a receipt now would attest bytes \
             the run never judged. Not recording"
        )?;
        return Ok(ExitCode::Violation);
    }
    // THE RUN'S WALL TIME RIDES THE RECEIPT (CLOUD-2776), between the stamp and
    // the key, so a hit can say what the run it stands for cost. The key stays
    // the last field, which is all `stored_key` reads.
    let stamp = crate::clock::rfc3339_utc(crate::clock::now_unix());
    let mut receipt = elapsed.map_or_else(
        || format!("{stamp} {expected}\n"),
        |elapsed| format!("{stamp} {}ms {expected}\n", elapsed.as_millis()),
    );
    if let Some((failure, flaky)) = failed {
        receipt = failure_body(&receipt, failure, flaky);
    }
    let written = git_dir.as_deref().map(|git_dir| {
        crate::record::keyed_group_write(git_dir, RECEIPTS, step, &expected, &receipt)
    });
    if !matches!(written, Some(Ok(()))) {
        writeln!(
            err,
            "step record: {step} — could not write the receipt; the next run re-derives"
        )?;
        return Ok(ExitCode::Internal);
    }
    if let Some(git_dir) = git_dir.as_deref() {
        // Housekeeping after the receipt is durable, so its failure costs disk,
        // never the receipt just written.
        let _ = crate::record::keyed_remove(git_dir, SUPERSEDED_RECEIPTS, step);
        let entries: Vec<(String, String)> =
            crate::record::keyed_group_entries(git_dir, RECEIPTS, step)
                .into_iter()
                .map(|(name, value)| (name, receipt_stamp(&value)))
                .collect();
        for name in evict(&entries, KEPT_RECEIPTS) {
            let _ = crate::record::keyed_group_remove(git_dir, RECEIPTS, step, &name);
        }
    }
    let what = if failed.is_some() { "failure " } else { "" };
    writeln!(
        said,
        "step record: {step} — recorded {what}{}",
        shown(&expected)
    )?;
    Ok(ExitCode::Success)
}

/// A pass's receipt line made a failure's: the code after the key, so the key
/// is no longer the line's last field, then the pointers.
fn failure_body(pass: &str, failure: &Failure, flaky: bool) -> String {
    use std::fmt::Write as _;
    let mut body = format!(
        "{} exit {}{}\n",
        pass.trim_end(),
        failure.code,
        if flaky { " flaky" } else { "" }
    );
    for (tag, value) in [("log", &failure.log), ("cases", &failure.cases)] {
        if let Some(value) = value {
            let _ = writeln!(body, "{tag} {value}");
        }
    }
    body
}

/// `batten step check <step> [--arg V]...`: `hit` or `miss`, in words, at exit 0.
///
/// Always exit 0: every way a key fails to form, an authority that will not load
/// included, is a `miss` that runs the step.
///
/// # Errors
///
/// An I/O error when the answer cannot be written.
pub fn run_check(step: &str, args: &[String], out: &mut dyn Write) -> Result<ExitCode> {
    let answer = check(step, args, None);
    writeln!(out, "{}", answer.line(step))?;
    Ok(ExitCode::Success)
}

/// `batten step record <step> [--arg V]...`: write the receipt a paired check
/// made possible.
///
/// Exit 2 when it refuses — no pending key, or the key moved while the step ran
/// (an authority that no longer loads is such a move) — because that is a
/// statement about the tree, not the invocation; exit 3 when the store will not
/// take the write.
///
/// # Errors
///
/// An I/O error when a line cannot be written.
pub fn run_record(
    step: &str,
    args: &[String],
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    record(step, args, None, None, out, err)
}

/// `batten step run <step> [--arg V]... -- <command...>`: the pair composed.
///
/// A hit exits 0 without running anything. A miss runs the command through
/// [`crate::exec::run`], whose code is the verb's — a child's `2` stays `2` —
/// and records only after a zero exit. The check's words and the record's note
/// go to `err`, because stdout belongs to the child.
///
/// THE STEP'S VERDICT IS THE COMMAND'S, AND NOTHING ELSE'S. The cache's own
/// lines are best-effort — a stderr that will not take them never stops the
/// command running and never turns its code into another — and the record after
/// a pass is an economy whose every failure is swallowed.
///
/// # Errors
///
/// A [`crate::Passthrough`] carrying the command's non-zero code, and a
/// [`crate::error::UsageError`] when the command cannot be started — each
/// [`crate::exec::run`]'s own, passed through unchanged.
pub fn run_step(
    step: &str,
    args: &[String],
    command: &[String],
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // ONE RUNNER PER STEP AT A TIME (CLOUD-2783). hk's hooks start the same
    // step in parallel, each found no receipt, and each ran it: measured on lap
    // 33, `lint:clippy` ran three times at once, ~20 minutes a lap. Held across
    // check, run and record, so a second runner waits, then reads the first's
    // receipt as a hit. A lock that cannot be taken runs unlocked: it is an
    // economy, and the step's verdict is its command's alone.
    let _held = step_lock(step);
    let answer = check(step, args, Some(command));
    let _ = writeln!(err, "{}", answer.line(step));
    if let Answer::Hit(key) = &answer {
        // A HIT REPORTS THE RUN IT STANDS FOR (CLOUD-2776), never its own few
        // milliseconds: a resumed lap must not look faster than the work was.
        // The matched record is the one for this key (CLOUD-2784).
        let recorded = crate::git::git_dir(Path::new("."))
            .ok()
            .and_then(|git_dir| crate::record::keyed_group_read(&git_dir, RECEIPTS, step, key))
            .and_then(|body| recorded_millis(&body));
        let _ = writeln!(err, "{}", stage_line(step, "hit", recorded));
        record_pass(step);
        return Ok(ExitCode::Success);
    }
    if let Answer::Red(key, failure) = &answer {
        return answer_red(step, key, failure, err);
    }
    let started = std::time::Instant::now();
    // TEED, NOT ONLY CAPTURED (CLOUD-2091). `exec::run`'s default stores the
    // child's bytes and prints none of them, which is right for `batten exec` and
    // wrong here: a step is a gate whose reader is a log, and on a CI runner the
    // capture store dies with the job. A failing `test:cargo` then said only
    // `ERROR task failed`, with no case named anywhere a person could read it.
    let mut settings = crate::config_model::ExecConfig::DEFAULT;
    settings.tee = true;
    // A MISS KEEPS WHAT IT FINISHES, CASE BY CASE, when the command is a
    // nextest run (CLOUD-2772): a stopped run resumes rather than re-running
    // every case it passed. Keyed by the command's own argv, never a config key,
    // so the released engine reading the authority meets nothing new. The
    // receipt's key stays the declared command's; a journal that cannot be set
    // up runs the command as declared, because the journal is an economy and
    // the step's verdict is the command's alone.
    // BY THE ROW, NEVER BY THE ARGV (CLOUD-2785): `journal = "nextest"`. NOT
    // UNDER CI (CLOUD-2850), for "Local only"'s reason: a runner that kept the
    // journal would answer a case from an earlier run.
    let journaled = declared(step)
        .filter(|_| !under_ci())
        .is_some_and(|row| row.journal == Some(crate::step_table::Journal::Nextest))
        .then_some(command)
        .and_then(|_| crate::git::repo_root(Path::new(".")).ok())
        .and_then(|root| Some((crate::mutate::resume::journaled(&root, command).ok()?, root)));
    let running = journaled
        .as_ref()
        .map_or(command, |(argv, _)| argv.as_slice());
    // A MISS ON LINUX IS TRACED (CLOUD-2784), so a read outside the row's
    // declared inputs is seen before a receipt is minted over it. Where no
    // tracer answers the step runs untraced and records as before.
    let traced = answer
        .recording()
        .is_some()
        .then(crate::mutate::trace::tracer)
        .flatten()
        .and_then(|strace| Some((strace, trace_file(step)?)));
    let spawned: Vec<String> = match (&traced, running.split_first()) {
        (Some((strace, file)), Some((program, rest))) => std::iter::once(strace.clone())
            .chain(crate::mutate::trace::trace_args(file, program, rest))
            .collect(),
        _ => running.to_vec(),
    };
    let mut report = Vec::new();
    let ran = crate::exec::run_with(&spawned, &[], &settings, &mut report);
    // THE RUN'S DEPENDENCY PASSES OUTLIVE IT only over a tree that stood for
    // the whole of it; an economy either way, so its failure is swallowed.
    if let Some((_, root)) = &journaled {
        let _ = crate::mutate::resume::promote(root);
    }
    let elapsed = started.elapsed();
    let passed = matches!(ran, Ok(ExitCode::Success));
    if !passed {
        let run = Ran {
            root: journaled.as_ref().map(|(_, root)| root.as_path()),
            outcome: &ran,
            elapsed,
            report: &report,
        };
        after_failure(step, args, command, answer.recording().is_some(), &run, err);
    }
    let linted = traced
        .as_ref()
        .filter(|_| passed)
        .map(|(_, file)| lint_trace(step, file));
    // THE TRACE IS READ ONCE, THEN REMOVED, pass or fail (lap 16): a whole
    // test run traces to gigabytes, so one kept per step filled the disk. The
    // listing beside it is what a reader needs, and it stays.
    if let Some((_, file)) = &traced {
        let _ = std::fs::remove_file(file);
    }
    // A HAZARD OR AN UNREAD TRACE ENDS THE STEP UNRECORDED: `Some(code)` is
    // the hazard's own, `None` leaves the step's verdict standing.
    match linted.map(|linted| lint_stop(step, linted, err)) {
        Some(LintStop::Fail) => return Ok(ExitCode::Violation),
        Some(LintStop::Unrecorded) => return ran,
        Some(LintStop::Go) | None => {}
    }
    if passed && answer.recording().is_some() {
        // A record that refuses or fails here — the inputs moved while the
        // command ran, the store would not take the write — costs the next run
        // a re-derive and says so on stderr. Its `Result` is discarded, never
        // `?`-propagated: a passing step stays a passing step.
        let mut recorded = Vec::new();
        let mut refused = Vec::new();
        let _ = record(
            step,
            args,
            Some(command),
            Some(elapsed),
            &mut recorded,
            &mut refused,
        );
        let _ = err.write_all(&recorded);
        let _ = err.write_all(&refused);
    }
    if passed {
        record_pass(step);
    }
    let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let _ = writeln!(err, "{}", stage_line(step, "ran", Some(millis)));
    ran
}

/// The keyed family a step's last pass is filed under (CLOUD-2788): per step
/// id, the tree id of `HEAD` it passed at.
///
/// A PASS, NOT A RECEIPT KEY. `step cover` asks whether a row passed at this
/// tree, and a receipt key cannot answer that: it depends on the `--arg`s the
/// caller passed, which a later verb does not have, and a schedule-only row
/// takes no receipt at all.
pub const PASSES: &str = "step-passes";

/// File that `step` passed at `HEAD`'s tree. Best-effort: a store that will not
/// take it costs `step cover` a refusal later, never this step its verdict.
fn record_pass(step: &str) {
    let root = Path::new(".");
    let (Ok(git_dir), Ok(Some(tree))) = (
        crate::git::git_dir(root),
        crate::git::resolve_ref(root, "HEAD^{tree}"),
    ) else {
        return;
    };
    let _ = crate::record::keyed_write(&git_dir, PASSES, step, &format!("{tree}\n"));
}

/// A KNOWN FAILURE IS ANSWERED, NOT RE-RUN (CLOUD-2253): its code, the pointer
/// to its log, the cases and the command that confirms a fix, and a word to a
/// supervising lap, which stops at once. The code is the recorded run's.
fn answer_red(step: &str, key: &str, failure: &Failure, err: &mut dyn Write) -> Result<ExitCode> {
    say_failure(step, failure, err);
    let recorded = crate::git::git_dir(Path::new("."))
        .ok()
        .and_then(|git_dir| crate::record::keyed_group_read(&git_dir, RECEIPTS, step, key))
        .and_then(|body| recorded_millis(&body));
    let _ = writeln!(err, "{}", stage_line(step, "red", recorded));
    red_to_supervisor(step);
    Err(crate::error::Passthrough::raise(failure.code))
}

/// What a traced pass's lint leaves the step to do.
enum LintStop {
    /// A written or undeclared input: the step fails, unrecorded.
    Fail,
    /// A trace that cannot be read whole: no receipt, the verdict stands.
    Unrecorded,
    /// Nothing the lint can see: on to the record.
    Go,
}

/// What a traced pass's lint ends the step with, saying why on `err`.
fn lint_stop(step: &str, linted: Linted, err: &mut dyn Write) -> LintStop {
    match linted {
        Linted::Wrote(count, listing) => {
            let _ = writeln!(
                err,
                "step run: {step} wrote {count} declared input(s); read {}",
                listing.display()
            );
            LintStop::Fail
        }
        Linted::Undeclared(count, listing) => {
            let _ = writeln!(
                err,
                "step run: {step} read {count} path(s) outside its inputs; read {}",
                listing.display()
            );
            LintStop::Fail
        }
        // The row no longer reads (the command moved the authority): the
        // record below recomputes the key and refuses on its own words.
        Linted::Declared | Linted::RowUnread => LintStop::Go,
        Linted::Unread => {
            // A trace that cannot be read whole proves nothing about the
            // declaration, so no receipt: the step's own verdict stands.
            let _ = writeln!(
                err,
                "step run: {step} — its trace could not be read whole; not recording"
            );
            LintStop::Unrecorded
        }
    }
}

/// What a failed run left for [`after_failure`].
struct Ran<'a> {
    /// The checkout a journaled run ran in, which holds its report.
    root: Option<&'a Path>,
    /// The run's own answer.
    outcome: &'a Result<ExitCode>,
    /// How long it ran.
    elapsed: std::time::Duration,
    /// `exec`'s record of it, which names the stored streams.
    report: &'a [u8],
}

/// After a failed run: the flaky-suspect label and the failing cases with
/// the command that confirms a fix (a journaled run's), then the failure
/// receipt where the answer had a key and the code is a verdict (CLOUD-2253).
fn after_failure(
    step: &str,
    args: &[String],
    command: &[String],
    keyed: bool,
    run: &Ran<'_>,
    err: &mut dyn Write,
) {
    let flaky = run.root.and_then(|root| report_flaky(step, root, err));
    let cases = run.root.and_then(|root| failed_cases_said(root, command));
    if let Some(cases) = &cases {
        let _ = writeln!(err, "step run: {step} {cases}");
    }
    let code = run
        .outcome
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<crate::error::Passthrough>())
        .map(|carried| carried.0)
        .filter(|code| recordable_failure(*code));
    if let (Some(code), true) = (code, keyed) {
        let failure = Failure {
            code,
            log: logged(run.report),
            cases,
        };
        let all_suspect =
            matches!(flaky, Some((suspects, failed)) if failed > 0 && suspects == failed);
        record_failure(
            step,
            args,
            command,
            run.elapsed,
            (&failure, all_suspect),
            err,
        );
    }
}

/// THE FAILURE IS RECORDED LIKE A PASS, under the key the check filed, and
/// every refusal and store failure is swallowed the same way: the step's
/// verdict is its command's, and the receipt is an economy.
fn record_failure(
    step: &str,
    args: &[String],
    command: &[String],
    elapsed: std::time::Duration,
    failed: (&Failure, bool),
    err: &mut dyn Write,
) {
    let mut recorded = Vec::new();
    let mut refused = Vec::new();
    let _ = record_as(
        step,
        args,
        Some(command),
        Some(elapsed),
        Some(failed),
        &mut recorded,
        &mut refused,
    );
    let _ = err.write_all(&recorded);
    let _ = err.write_all(&refused);
}

/// The keyed family a step answered from a failure receipt is filed under,
/// keyed by the supervising task's pid (CLOUD-2253): the lap's gate arm reads
/// it and cancels the gate at once, so a known-red tree costs seconds.
pub const RED: &str = "step-red";

/// File that `step` was answered red under the task exported in [`TASK_PID`].
/// Best-effort, like every supervisor write: no supervisor is a no-op.
fn red_to_supervisor(step: &str) {
    let Some(pid) = std::env::var(TASK_PID).ok().filter(|pid| !pid.is_empty()) else {
        return;
    };
    let Ok(git_dir) = crate::git::git_dir(Path::new(".")) else {
        return;
    };
    let _ = crate::record::keyed_write(&git_dir, RED, pid.trim(), &format!("{step}\n"));
}

/// The step a receipt-answered failure filed under task `pid`, if any.
pub(crate) fn red_under(git_dir: &Path, pid: u32) -> Option<String> {
    crate::record::keyed_read(git_dir, RED, &pid.to_string())
        .map(|step| step.trim().to_owned())
        .filter(|step| !step.is_empty())
}

/// Clear what [`red_under`] reads, before a gate starts under `pid`.
pub(crate) fn clear_red(git_dir: &Path, pid: u32) {
    let _ = crate::record::keyed_remove(git_dir, RED, &pid.to_string());
}

/// A failure's pointer lines: the code and the stored log's handles, then the
/// cases and the focused command. Pointers only, never the log (rule 4).
fn say_failure(step: &str, failure: &Failure, err: &mut dyn Write) {
    let _ = match &failure.log {
        Some(log) => writeln!(
            err,
            "step run: {step} failed with exit {}; read {log}",
            failure.code
        ),
        None => writeln!(err, "step run: {step} failed with exit {}", failure.code),
    };
    if let Some(cases) = &failure.cases {
        let _ = writeln!(err, "step run: {step} {cases}");
    }
}

/// The capture handles `exec`'s record names, space-separated: the
/// `exec: <stream> <n> byte(s) <handle>` lines' last fields.
fn logged(report: &[u8]) -> Option<String> {
    let handles: Vec<&str> = std::str::from_utf8(report)
        .ok()?
        .lines()
        .filter(|line| line.starts_with("exec: ") && line.contains(" byte(s) "))
        .filter_map(|line| line.split_whitespace().last())
        .collect();
    (!handles.is_empty()).then(|| handles.join(" "))
}

/// A journaled run's failing cases and the command that confirms a fix: the
/// step's own argv before any `--`, filtered to exactly those cases.
fn failed_cases_said(root: &Path, command: &[String]) -> Option<String> {
    let failed = crate::mutate::resume::failed(root)?;
    if failed.is_empty() {
        return None;
    }
    let names: Vec<String> = failed
        .iter()
        .map(|(name, binary)| format!("{binary} {name}"))
        .collect();
    let filter = failed
        .iter()
        .map(|(name, binary)| format!("(binary_id({binary}) & test(={name}))"))
        .collect::<Vec<_>>()
        .join(" | ");
    let program: Vec<String> = command
        .iter()
        .take_while(|word| word.as_str() != "--")
        .map(|word| shell_word(word))
        .collect();
    Some(format!(
        "failed {} case(s): {}; confirm a fix with: {} -E {}",
        failed.len(),
        names.join(", "),
        program.join(" "),
        shell_word(&filter)
    ))
}

/// `word` as one shell word: bare where nothing in it is special, otherwise
/// single-quoted.
fn shell_word(word: &str) -> String {
    let plain = !word.is_empty()
        && word
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || "_-./:=@,+".contains(ch));
    if plain {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The roster `step cover` covers: the host's required check names.
pub const ROSTER_VAR: &str = "CI_REQUIRED_CHECKS";

/// Which local step stands for each required check: `check=step` pairs,
/// comma-separated (CLOUD-2788).
pub const PROOF_VAR: &str = "CI_LOCAL_PROOF";

/// The required checks no local run stands for: names, or prefixes ending in
/// `*`, comma-separated (CLOUD-2788).
pub const EXEMPT_VAR: &str = "CI_EXEMPT_CHECKS";

/// The non-empty, trimmed entries of a comma-separated variable's value.
fn listed(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// Whether the exemption `entry` covers the required check `check`: equal, or
/// a prefix when `entry` ends in `*`.
fn exempts(entry: &str, check: &str) -> bool {
    entry
        .strip_suffix('*')
        .map_or(entry == check, |prefix| check.starts_with(prefix))
}

/// What `step cover` refuses: the roster entries with neither a pass of their
/// step at `tree` nor an exemption, and the mapped checks the roster does not
/// hold. Pure over `passed`, a step id's recorded pass tree.
fn cover_gaps<'a>(
    roster: &[&'a str],
    proof: &[(&'a str, &'a str)],
    exempt: &[&str],
    tree: &str,
    passed: &dyn Fn(&str) -> Option<String>,
) -> (Vec<&'a str>, Vec<&'a str>) {
    let uncovered = roster
        .iter()
        .copied()
        .filter(|check| {
            !exempt.iter().any(|entry| exempts(entry, check))
                && !proof.iter().any(|(mapped, step)| {
                    mapped == check && passed(step).is_some_and(|at| at.trim() == tree)
                })
        })
        .collect();
    let stale = proof
        .iter()
        .map(|(mapped, _)| *mapped)
        .filter(|mapped| !roster.contains(mapped))
        .collect();
    (uncovered, stale)
}

/// `step cover` (CLOUD-2788): exit 0 iff every check [`ROSTER_VAR`] names is
/// covered by the step [`PROOF_VAR`] maps it to having passed at `HEAD`'s
/// tree, or by an [`EXEMPT_VAR`] entry; 2 naming each uncovered check and each
/// mapped check the roster does not hold; 1 for a malformed mapping; 3 when
/// the roster is unset or `HEAD` names no tree.
///
/// ALL THREE FROM THE ENVIRONMENT, never `batten.toml` or an argument: check
/// names carry spaces (`mutants (0)`), and the roster, which checks have a
/// local counterpart and which are exempt are the consumer's CI vocabulary
/// (rule 1), declared where its task runner already declares the roster.
///
/// # Errors
///
/// `out` or `err` cannot be written.
pub fn run_cover(out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let var = |name: &str| std::env::var(name).unwrap_or_default();
    let (roster, proof, exempt) = (var(ROSTER_VAR), var(PROOF_VAR), var(EXEMPT_VAR));
    let roster = listed(&roster);
    if roster.is_empty() {
        writeln!(
            err,
            "step cover: {ROSTER_VAR} is unset, so there is no roster to cover"
        )?;
        return Ok(ExitCode::Internal);
    }
    let mut pairs = Vec::new();
    for entry in listed(&proof) {
        let Some((check, step)) = entry
            .split_once('=')
            .map(|(check, step)| (check.trim(), step.trim()))
            .filter(|(check, step)| !check.is_empty() && !step.is_empty())
        else {
            writeln!(
                err,
                "step cover: {PROOF_VAR} entry is not check=step: {entry}"
            )?;
            return Ok(ExitCode::Usage);
        };
        pairs.push((check, step));
    }
    let exempt = listed(&exempt);
    let root = Path::new(".");
    let (Ok(git_dir), Ok(Some(tree))) = (
        crate::git::git_dir(root),
        crate::git::resolve_ref(root, "HEAD^{tree}"),
    ) else {
        writeln!(err, "step cover: HEAD names no tree")?;
        return Ok(ExitCode::Internal);
    };
    let passed = |step: &str| crate::record::keyed_read(&git_dir, PASSES, step);
    let (uncovered, stale) = cover_gaps(&roster, &pairs, &exempt, &tree, &passed);
    let stale: Vec<String> = stale
        .iter()
        .map(|check| format!("{PROOF_VAR} maps {check}"))
        .collect();
    for check in &uncovered {
        writeln!(out, "uncovered {check}")?;
    }
    for line in &stale {
        writeln!(out, "stale {line}")?;
    }
    if uncovered.is_empty() && stale.is_empty() {
        writeln!(
            err,
            "step cover: {} required check(s) covered",
            roster.len()
        )?;
        return Ok(ExitCode::Success);
    }
    writeln!(
        err,
        "step cover: {} required check(s) without a pass or exemption, {} stale mapping(s)",
        uncovered.len(),
        stale.len()
    )?;
    Ok(ExitCode::Violation)
}

/// A RED JOURNALED RUN SAYS WHETHER THE CHANGE COULD HAVE CAUSED IT
/// (CLOUD-2786): a failed case whose sealed reach still holds ran nothing that
/// moved. A label beside the trace, never a verdict: the run's exit stands.
/// Returns the suspects and the failed count, which decide whether the
/// failure receipt re-runs (CLOUD-2253).
fn report_flaky(step: &str, root: &Path, err: &mut dyn Write) -> Option<(usize, usize)> {
    use std::fmt::Write as _;
    let (suspects, failed) = crate::mutate::resume::flaky_suspects(root)?;
    let counts = (suspects.len(), failed);
    let Some(listing) = trace_file(step)
        .map(|file| file.with_extension("flaky"))
        .filter(|_| failed > 0)
    else {
        return Some(counts);
    };
    let body = suspects
        .iter()
        .fold(String::new(), |mut body, (name, binary)| {
            let _ = writeln!(body, "{binary} {name}");
            body
        });
    if crate::durable::replace(&listing, body).is_ok() {
        let _ = writeln!(
            err,
            "step run: {step} flaky-suspect {} of {failed} failing case(s); read {}",
            suspects.len(),
            listing.display()
        );
    }
    Some(counts)
}

/// Where a step's traced run writes its trace: a file directly under the git
/// dir, which exists, so nothing is created here; the run removes it once
/// linted. `None` where the git dir cannot be found, which runs the step
/// untraced.
fn trace_file(step: &str) -> Option<std::path::PathBuf> {
    let git_dir = crate::git::git_dir(Path::new(".")).ok()?;
    Some(git_dir.join(format!(
        "{TRACES}-{}.trace",
        crate::tools::digest(step.as_bytes())
    )))
}

/// The exclusive lock one runner of `step` holds (CLOUD-2783), blocking until
/// any other runner of the same step lets go; released when the file drops.
/// `None` where the git dir or the lock cannot be had.
fn step_lock(step: &str) -> Option<std::fs::File> {
    let git_dir = crate::git::git_dir(Path::new(".")).ok()?;
    step_lock_at(&git_dir, step)
}

/// [`step_lock`] under an explicit git dir, for a case to hold.
fn step_lock_at(git_dir: &Path, step: &str) -> Option<std::fs::File> {
    let path = git_dir.join(format!("{LOCKS}-{}", crate::tools::digest(step.as_bytes())));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .ok()?;
    file.lock().ok()?;
    Some(file)
}

/// The prefix of each step's run lock under the git dir.
const LOCKS: &str = "batten-step-lock";

/// Remove every step trace under `git_dir` whose step no runner holds, and
/// answer how many and how many bytes (CLOUD-2783).
///
/// A run removes its own trace once read, but a run that is killed first
/// leaves it: a stopped lap left a 15 GB `ci-suite` trace in `.git`, and the
/// disk admission refused the next lap with nothing it could collect. A trace
/// and its step's lock share one digest, so a trace whose lock can be taken has
/// no writer: that is the whole test, exact rather than an age guess.
#[must_use]
pub fn sweep_orphaned_traces(git_dir: &Path) -> (usize, u64) {
    let mut swept = (0, 0);
    for entry in std::fs::read_dir(git_dir).into_iter().flatten().flatten() {
        let name = entry.file_name();
        let Some(digest) = name
            .to_str()
            .and_then(|name| name.strip_prefix(&format!("{TRACES}-")))
            .and_then(|rest| rest.strip_suffix(".trace"))
        else {
            continue;
        };
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(git_dir.join(format!("{LOCKS}-{digest}")));
        let free = lock.as_ref().is_ok_and(|file| file.try_lock().is_ok());
        if !free {
            continue;
        }
        let bytes = entry.metadata().map_or(0, |meta| meta.len());
        if std::fs::remove_file(entry.path()).is_ok() {
            swept.0 += 1;
            swept.1 += bytes;
        }
    }
    swept
}

/// The prefix of each step's last trace, and its undeclared listing, under the
/// git dir.
const TRACES: &str = "batten-step-trace";

/// What a traced run's reads say about its row's declaration.
enum Linted {
    /// Every read was declared, outside the worktree, or ignored.
    Declared,
    /// This many worktree paths were read undeclared; the listing names them.
    Undeclared(usize, std::path::PathBuf),
    /// This many declared inputs were written (CLOUD-2786); the listing names
    /// them. Checked before [`Linted::Undeclared`].
    Wrote(usize, std::path::PathBuf),
    /// The trace could not be read whole, so nothing is proven.
    Unread,
    /// The row no longer reads; the record's own recompute decides.
    RowUnread,
}

/// Read `file`'s trace against `step`'s declared inputs, writing the
/// undeclared paths, one per line, beside it.
fn lint_trace(step: &str, file: &Path) -> Linted {
    let (Some(row), Ok(root)) = (declared(step), crate::git::repo_root(Path::new("."))) else {
        return Linted::RowUnread;
    };
    let root = crate::git::canonical(&root);
    let cwd = std::env::current_dir()
        .ok()
        .map(|dir| crate::git::canonical(&dir));
    let Some(accessed) = crate::mutate::trace::await_trace(file)
        .as_deref()
        .and_then(|text| crate::mutate::trace::accesses(text, cwd.as_deref()))
    else {
        return Linted::Unread;
    };
    let mut cache = BTreeMap::new();
    let mut ignored = |path: &str| {
        *cache
            .entry(path.to_owned())
            .or_insert_with(|| crate::git::check_ignore(&root, path).unwrap_or(false))
    };
    // THE WRITE HAZARD FIRST (CLOUD-2786): a run that wrote a declared input
    // and put it back leaves the key unmoved, though its verdict judged bytes
    // the tree never held (Rattle, Spall et al. OOPSLA 2020).
    let written: Vec<std::path::PathBuf> = accessed
        .iter()
        .filter(|(_, access)| *access == crate::mutate::trace::Access::Write)
        .map(|(path, _)| path.clone())
        .collect();
    let wrote = written_inputs(&root, row.inputs(), &written, &mut ignored);
    if !wrote.is_empty() {
        let listing = file.with_extension("wrote");
        let mut body = wrote.join("\n");
        body.push('\n');
        if crate::durable::replace(&listing, body).is_err() {
            return Linted::Unread;
        }
        return Linted::Wrote(wrote.len(), listing);
    }
    let touched: Vec<std::path::PathBuf> = accessed.into_iter().map(|(path, _)| path).collect();
    let found = undeclared(&root, row.inputs(), &touched, &mut ignored);
    if found.is_empty() {
        return Linted::Declared;
    }
    let listing = file.with_extension("undeclared");
    let mut body = found.join("\n");
    body.push('\n');
    if crate::durable::replace(&listing, body).is_err() {
        return Linted::Unread;
    }
    Linted::Undeclared(found.len(), listing)
}

/// The declared inputs among `written` (CLOUD-2786): a worktree path under
/// `root`, outside the git dir, that a declared pathspec selects and that
/// `ignored` does not answer for, an ignored ancestor answering for all
/// beneath it — so a build's `target/` writes never count. Sorted, each once.
fn written_inputs(
    root: &Path,
    inputs: &[String],
    written: &[std::path::PathBuf],
    ignored: &mut dyn FnMut(&str) -> bool,
) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for path in written {
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.is_empty() || relative == ".git" || relative.starts_with(".git/") {
            continue;
        }
        if inputs
            .iter()
            .any(|spec| crate::git::pathspec_matches(spec, &relative))
        {
            out.insert(relative);
        }
    }
    out.into_iter()
        .filter(|relative| {
            let mut ancestors: Vec<&str> = relative
                .match_indices('/')
                .map(|(at, _)| &relative[..at])
                .collect();
            ancestors.push(relative);
            !ancestors.into_iter().any(&mut *ignored)
        })
        .collect()
}

/// The key's `env` lines for `declared` over `vars` (CLOUD-2786), sorted: one
/// `env "NAME=value"` per variable it keys ([`DeclaredEnv::keys`]), and one
/// `env "PATTERN" none` per declaration nothing matched. `None` where a keyed
/// value is not Unicode, which is no key.
///
/// [`DeclaredEnv::keys`]: crate::mutate::resume::DeclaredEnv::keys
fn env_lines(
    declared: &crate::mutate::resume::DeclaredEnv,
    vars: impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)>,
) -> Option<Vec<String>> {
    let mut lines = std::collections::BTreeSet::new();
    let mut matched = std::collections::BTreeSet::new();
    for (name, value) in vars {
        let Some(name) = name.to_str() else {
            continue;
        };
        if !declared.keys(name) {
            continue;
        }
        let value = value.to_str()?;
        lines.insert(format!("env {}", quoted(&format!("{name}={value}"))));
        for pattern in &declared.env {
            if crate::mutate::resume::env_matches(name, pattern) {
                matched.insert(pattern.as_str());
            }
        }
    }
    for pattern in &declared.env {
        if !matched.contains(pattern.as_str()) {
            lines.insert(format!("env {} none", quoted(pattern)));
        }
    }
    Some(lines.into_iter().collect())
}

/// The worktree paths among `touched` that `inputs` does not declare (CLOUD-2784).
///
/// Kept out: a path outside `root` (the toolchain, which `tools` keys), the git
/// dir, the root itself and every ancestor directory of a declared pathspec (a
/// run reaching a declared file walks them), anything a declared pathspec
/// selects ([`crate::git::pathspec_matches`], git's own reading), and anything
/// `ignored` answers for, judged ancestor first, so `target/` is asked once and
/// never per file beneath it. Sorted, each once.
fn undeclared(
    root: &Path,
    inputs: &[String],
    touched: &[std::path::PathBuf],
    ignored: &mut dyn FnMut(&str) -> bool,
) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for path in touched {
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if relative.is_empty() || relative == ".git" || relative.starts_with(".git/") {
            continue;
        }
        if inputs.iter().any(|spec| {
            crate::git::pathspec_matches(spec, &relative) || ancestor_of(&relative, spec)
        }) {
            continue;
        }
        out.insert(relative);
    }
    out.into_iter()
        .filter(|relative| {
            let mut ancestors: Vec<&str> = relative
                .match_indices('/')
                .map(|(at, _)| &relative[..at])
                .collect();
            ancestors.push(relative);
            !ancestors.into_iter().any(&mut *ignored)
        })
        .collect()
}

/// Whether `dir` is an ancestor directory of what `spec` selects: the literal
/// part of the spec, up to its first wildcard, lies beneath `dir`.
fn ancestor_of(dir: &str, spec: &str) -> bool {
    let spec = spec.strip_prefix("./").unwrap_or(spec);
    let literal = spec
        .find(['*', '?', '[', '\\'])
        .map_or(spec, |at| &spec[..at]);
    literal
        .strip_prefix(dir)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// A receipt's stamp: the first field of its first line, RFC 3339 in UTC, so
/// it orders as text. A receipt without one sorts first, as the oldest.
fn receipt_stamp(value: &str) -> String {
    value
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().next())
        .unwrap_or_default()
        .to_owned()
}

/// The names to drop so at most `cap` of `entries` remain: the oldest by stamp,
/// ties broken by name, first in first out. A hit writes nothing, so recency
/// is the write, never a read, and the read path stays write-free under
/// concurrent runs of one step.
fn evict(entries: &[(String, String)], cap: usize) -> Vec<String> {
    let mut ranked: Vec<&(String, String)> = entries.iter().collect();
    ranked.sort_by(|(a_name, a_stamp), (b_name, b_stamp)| {
        a_stamp.cmp(b_stamp).then_with(|| a_name.cmp(b_name))
    });
    let excess = ranked.len().saturating_sub(cap);
    ranked
        .into_iter()
        .take(excess)
        .map(|(name, _)| name.clone())
        .collect()
}

/// `batten step graph run <group>... [--jobs N]` (CLOUD-2785): every row of
/// each group, each as a child process from its `run` argv, a row starting only
/// once every `depends_on` exited 0, at most `jobs` at once (or the group's own
/// `NAME=N`).
///
/// THE GROUPS RUN IN ORDER AND A RED ONE STOPS NONE AFTER IT (CLOUD-2789). One
/// `step graph run` per tier made the task runner's `run` array the scheduler,
/// and it stops at the first failing line, so a lap reported one tier's reds
/// and the next tier's only on the lap after, once those were fixed. Here a
/// failure skips only the rows that name it in `depends_on`, and every red row
/// is listed once more at the end, so one run
/// reports every failure. A group still starts only after the one before it
/// has finished, which keeps the green path's phases, and so its wall time,
/// what the separate calls had.
///
/// A CHILD PROCESS PER NODE, never `run_step` on a thread: `check`, `record`
/// and `declared` read the working directory, `announce` pushes one phase per
/// process, and a tee writes to the process's own streams. The spawn is
/// [`crate::exec::run_with`], the placed boundary, so the inventory does not
/// grow; a node's lines carry its task runner's own prefix.
///
/// Prints one pointer line per node (`ran <code> <seconds>` or `skipped`) and
/// the peak concurrency reached, and exits with the worst node's code.
///
/// # Errors
///
/// An I/O error when a line cannot be written.
pub fn run_graph(groups: &[String], jobs: Option<&str>, err: &mut dyn Write) -> Result<ExitCode> {
    let positive = |text: &str| text.parse::<std::num::NonZeroUsize>().ok();
    let jobs = match jobs.map(positive) {
        None => None,
        Some(Some(jobs)) => Some(jobs),
        Some(None) => {
            writeln!(err, "step graph: --jobs takes a positive integer")?;
            return Ok(ExitCode::Usage);
        }
    };
    let steps = match crate::resolve::committed(Path::new("."), &Overrides::default()) {
        Ok(config) => config.steps,
        Err(error) => {
            writeln!(err, "step graph: the step table did not load: {error}")?;
            return Ok(ExitCode::Usage);
        }
    };
    // EVERY GROUP IS RESOLVED BEFORE ANY ROW RUNS, so a misspelt third group is
    // a usage error, not a refusal an hour in.
    let mut phases: Vec<(&str, Vec<&Step>, Option<std::num::NonZeroUsize>)> = Vec::new();
    for spelled in groups {
        let (group, bound) = match spelled.split_once('=') {
            None => (spelled.as_str(), jobs),
            Some((group, bound)) => {
                let Some(bound) = positive(bound) else {
                    writeln!(
                        err,
                        "step graph: {spelled}: a group's bound is a positive integer"
                    )?;
                    return Ok(ExitCode::Usage);
                };
                (group, Some(bound))
            }
        };
        let rows: Vec<&Step> = steps
            .iter()
            .filter(|row| row.group.as_deref() == Some(group))
            .collect();
        if rows.is_empty() {
            writeln!(err, "step graph: no [[step]] row is in group {group}")?;
            return Ok(ExitCode::Usage);
        }
        phases.push((group, rows, bound));
    }
    let mut done: BTreeMap<String, i32> = BTreeMap::new();
    let mut worst = 0_i32;
    for (group, rows, bound) in &phases {
        let outcome = graph_phase(rows, *bound, &mut done);
        for line in &outcome.lines {
            writeln!(err, "step graph: {line}")?;
        }
        writeln!(
            err,
            "step graph: {group} peak {} of {}",
            outcome.peak,
            bound.map_or_else(|| String::from("unbounded"), |jobs| jobs.to_string())
        )?;
        worst = worst.max(outcome.worst);
    }
    // THE LAP'S ONE LIST OF REDS (CLOUD-2789): every row that ran and failed, in
    // run order, after every group has finished — the pointer each needs is its
    // id and code, and its own output is above, under its runner's prefix.
    for (group, rows, _) in &phases {
        for row in rows {
            if let Some(code) = done.get(&row.id).filter(|code| **code != 0) {
                let how = if *code == SKIPPED {
                    String::from("skipped")
                } else {
                    format!("ran {code}")
                };
                writeln!(err, "step graph: red {group} {} {how}", row.id)?;
            }
        }
    }
    if worst == 0 {
        return Ok(ExitCode::Success);
    }
    ExitCode::from_code(worst).map_or_else(|| Err(crate::error::Passthrough::raise(worst)), Ok)
}

/// The code a skipped row is recorded under: never a code a child exits with,
/// so the red list can tell a row that ran and failed from one that never ran.
const SKIPPED: i32 = -1;

/// One group of [`run_graph`]: its rows, run as child processes, against the
/// codes every earlier group left in `done`.
fn graph_phase(
    rows: &[&Step],
    jobs: Option<std::num::NonZeroUsize>,
    done: &mut BTreeMap<String, i32>,
) -> Scheduled {
    let bound = jobs.map_or(usize::MAX, std::num::NonZeroUsize::get);
    schedule(rows, bound, done, &|row: &Step| {
        let mut settings = crate::config_model::ExecConfig::DEFAULT;
        settings.tee = true;
        let argv = row.run.clone().unwrap_or_default();
        // A NON-ZERO CHILD ARRIVES AS A `Passthrough` carrying its own code,
        // which may sit outside the §7 table; anything else is a spawn that
        // never decided, which is internal.
        let code = match crate::exec::run_with(&argv, &[], &settings, &mut std::io::sink()) {
            Ok(code) => code.code(),
            Err(error) => error
                .downcast_ref::<crate::error::Passthrough>()
                .map_or(ExitCode::Internal.code(), |carried| carried.0),
        };
        // A NODE THAT EXITS 0 PASSED AT THIS TREE (CLOUD-2788), schedule-only
        // nodes included: they take no receipt, and `step cover` reads this.
        if code == 0 {
            record_pass(&row.id);
        }
        code
    })
}

/// What a scheduled graph did: a pointer line per node, the most rows that ran
/// at once, and the worst code.
struct Scheduled {
    lines: Vec<String>,
    peak: usize,
    worst: i32,
}

/// Run `rows` as a dependency graph with at most `bound` at once, each through
/// `run`, recording each row's code in `done`. A `depends_on` names a row of
/// its own group (the step table refuses any other at load). Pure over `run`,
/// so the order, the bound and the skips are testable without a process.
fn schedule(
    rows: &[&Step],
    bound: usize,
    done: &mut BTreeMap<String, i32>,
    run: &(dyn Fn(&Step) -> i32 + Sync),
) -> Scheduled {
    let mut waiting: Vec<&Step> = rows.to_vec();
    let mut lines = Vec::new();
    let (mut running, mut peak) = (0_usize, 0_usize);
    let mut worst = 0_i32;
    std::thread::scope(|scope| {
        let (finished, arrivals) = std::sync::mpsc::channel::<(&str, i32, f64)>();
        loop {
            // A ROW WHOSE DEPENDENCY FAILED NEVER STARTS, and neither does any
            // row waiting on it: repeat until no skip uncovers another.
            while let Some((at, dependency)) = waiting.iter().enumerate().find_map(|(at, row)| {
                row.depends_on
                    .iter()
                    .find(|dependency| done.get(dependency.as_str()).is_some_and(|code| *code != 0))
                    .map(|dependency| (at, dependency.clone()))
            }) {
                let row = waiting.remove(at);
                lines.push(format!("{} skipped ({dependency} failed)", row.id));
                done.insert(row.id.clone(), SKIPPED);
            }
            while running < bound {
                let Some(at) = waiting.iter().position(|row| {
                    row.depends_on
                        .iter()
                        .all(|dependency| done.get(dependency.as_str()) == Some(&0))
                }) else {
                    break;
                };
                let row = waiting.remove(at);
                running += 1;
                peak = peak.max(running);
                let finished = finished.clone();
                scope.spawn(move || {
                    let started = std::time::Instant::now();
                    let code = run(row);
                    let _ = finished.send((row.id.as_str(), code, started.elapsed().as_secs_f64()));
                });
            }
            if running == 0 {
                break;
            }
            let Ok((id, code, seconds)) = arrivals.recv() else {
                break;
            };
            running -= 1;
            lines.push(format!("{id} ran {code} {seconds:.3}"));
            worst = worst.max(code);
            done.insert(id.to_owned(), code);
        }
    });
    Scheduled { lines, peak, worst }
}

/// The run time a receipt recorded: the `<n>ms` field of its first line, or
/// `None` for a receipt written before it carried one.
fn recorded_millis(body: &str) -> Option<u64> {
    body.lines()
        .next()?
        .split_whitespace()
        .find_map(|field| field.strip_suffix("ms")?.parse().ok())
}

/// `stage <step> <hit|ran> <seconds>`: one line per step, a count and never a
/// payload (rule 4), so a lap's log answers what each stage cost (CLOUD-2776).
/// A receipt too old to say is `-`.
fn stage_line(step: &str, how: &str, millis: Option<u64>) -> String {
    let seconds = millis.map_or_else(
        || String::from("-"),
        |millis| format!("{}.{:03}", millis / 1000, millis % 1000),
    );
    format!("stage {step} {how} {seconds}")
}

/// The digest `enforce --half tree --inputs-digest` prints when run in `dir`,
/// taken in-process: what the `[[step]]` cache keys that tool line on without
/// spawning a build and a policy load for it (step 17, this module).
///
/// # Errors
///
/// As [`tree_inputs_digest`].
pub fn tree_inputs_digest_in(dir: &Path) -> Result<String> {
    tree_inputs_digest(&crate::config::anchor_at(dir))
}

/// The digest `run_inputs_digest` prints.
///
/// # Errors
///
/// When the baseline's path does not resolve under `root`.
pub fn tree_inputs_digest(root: &Path) -> Result<String> {
    fn frame(hasher: &mut blake3::Hasher, label: &str, bytes: Option<&[u8]>) {
        hasher.update(label.as_bytes());
        hasher.update(b"\0");
        match bytes {
            Some(bytes) => {
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
            None => {
                hasher.update(b"none");
            }
        }
        hasher.update(b"\n");
    }
    let read =
        |path: Option<std::path::PathBuf>| path.and_then(|path| crate::fsio::read(path).ok());
    let mut hasher = blake3::Hasher::new();
    frame(
        &mut hasher,
        "baseline",
        read(crate::baseline::path(root)?).as_deref(),
    );
    let mut records: Vec<(String, Vec<u8>)> = crate::admission::store_dir(root)
        .ok()
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "json"))
        .filter_map(|entry| {
            let name = entry.file_name().into_string().ok()?;
            Some((name, crate::fsio::read(entry.path()).ok()?))
        })
        .collect();
    records.sort();
    frame(
        &mut hasher,
        "admissions",
        Some(&(records.len() as u64).to_le_bytes()),
    );
    for (name, bytes) in &records {
        frame(&mut hasher, &format!("admission {name}"), Some(bytes));
    }
    for rev in ["HEAD", "HEAD^2"] {
        let blocks = crate::git::commit_record(root, rev).ok().map(|record| {
            let mut text = String::new();
            for block in crate::admission::blocks(&record.body) {
                text.push_str(&block.claimed);
                text.push('\t');
                text.push_str(&crate::admission::canonical(&block.binding));
                text.push('\n');
            }
            text
        });
        frame(
            &mut hasher,
            &format!("blocks {rev}"),
            blocks.as_deref().map(str::as_bytes),
        );
    }
    frame(
        &mut hasher,
        "secret-key",
        read(crate::secrets::key_path(root).ok()).as_deref(),
    );
    frame(
        &mut hasher,
        crate::resolve::LOCAL_CONFIG_FILE,
        read(Some(root.join(crate::resolve::LOCAL_CONFIG_FILE))).as_deref(),
    );
    for name in crate::resolve::SETTINGS
        .iter()
        .filter_map(|setting| setting.env)
    {
        let value = std::env::var_os(name);
        frame(
            &mut hasher,
            name,
            value.as_ref().map(|value| value.as_encoded_bytes()),
        );
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    #[cfg(test)]
    #[test]
    fn a_held_step_lock_excludes_its_own_step_and_no_other() {
        // Fails by: the lock not exclusive (two runners of one step both run),
        // or keyed by something coarser than the step (two steps serialise).
        let dir = crate::scratch::scratch("step-lock");
        let held = step_lock_at(&dir, "lint:clippy").expect("the first runner locks");
        let path =
            |step: &str| dir.join(format!("{LOCKS}-{}", crate::tools::digest(step.as_bytes())));
        let same = std::fs::File::open(path("lint:clippy")).unwrap();
        assert!(
            matches!(same.try_lock(), Err(std::fs::TryLockError::WouldBlock)),
            "a second runner of the same step waits"
        );
        assert!(
            step_lock_at(&dir, "cross-check").is_some(),
            "another step is not held up"
        );
        drop(held);
        assert!(same.try_lock().is_ok(), "and the lock is released on drop");
    }

    #[test]
    fn only_a_trace_no_runner_holds_is_swept() {
        // Fails by: a live runner's trace removed from under it, or a killed
        // runner's trace kept for ever (the 15 GB that blocked lap 34).
        let dir = crate::scratch::scratch("step-trace-sweep");
        let trace = |step: &str| {
            dir.join(format!(
                "{TRACES}-{}.trace",
                crate::tools::digest(step.as_bytes())
            ))
        };
        std::fs::write(trace("running"), "live").unwrap();
        std::fs::write(trace("killed"), "orphaned").unwrap();
        let held = step_lock_at(&dir, "running").expect("the live runner locks");
        assert_eq!(sweep_orphaned_traces(&dir), (1, 8));
        assert!(trace("running").exists(), "a held step's trace stays");
        assert!(!trace("killed").exists(), "an unheld one is gone");
        drop(held);
    }

    #[test]
    fn the_stored_key_is_the_last_field_of_the_first_line() {
        assert_eq!(
            stored_key("2026-09-29T00:00:00Z abc\n").as_deref(),
            Some("abc")
        );
        assert_eq!(stored_key("abc\n").as_deref(), Some("abc"));
        // A blanked pending slot is no key, never an empty one that a blank
        // recomputation could match.
        assert_eq!(stored_key("\n"), None);
        assert_eq!(stored_key(""), None);
    }

    #[test]
    fn the_key_is_a_full_digest_and_a_line_shows_only_a_pointer_to_it() {
        let key = key_of("step \"a\"");
        assert_eq!(key.len(), 64);
        assert_ne!(key, key_of("step \"b\""));
        let line = Answer::Hit(key.clone()).line("a");
        assert!(line.starts_with("hit "), "{line}");
        assert!(line.contains(&key[..SHOWN]), "{line}");
        assert!(
            !line.contains(&key),
            "a line carries a pointer, not the key: {line}"
        );
    }

    /// Fails by: a receipt's `<n>ms` field misread, a receipt written before it
    /// carried one read as a time, or a stage line's seconds mis-rendered.
    /// Fails by: a prefix exemption matched only exactly, an exact one as a
    /// prefix, a pass at another tree or of another step counted, or a mapped
    /// check outside the roster dropped instead of reported.
    #[test]
    fn cover_counts_a_pass_at_this_tree_or_an_exemption() {
        assert!(super::exempts("windows", "windows"));
        assert!(!super::exempts("windows", "windows-arm"));
        assert!(super::exempts("dist (*", "dist (x86_64)"));
        assert!(!super::exempts("dist (*", "dist"));
        let roster = ["a", "b", "c", "win"];
        let proof = [("a", "sa"), ("b", "sb"), ("z", "sz")];
        let passed = |step: &str| match step {
            "sa" => Some(String::from("t1\n")),
            "sb" => Some(String::from("t0\n")),
            _ => None,
        };
        let (uncovered, stale) = super::cover_gaps(&roster, &proof, &["win"], "t1", &passed);
        assert_eq!(
            uncovered,
            ["b", "c"],
            "b passed at another tree, c is unmapped"
        );
        assert_eq!(stale, ["z"]);
    }

    #[test]
    fn a_stage_line_reads_the_recorded_run_and_renders_seconds() {
        assert_eq!(
            recorded_millis("2026-11-16T00:00:00Z 1250ms abc\n"),
            Some(1250)
        );
        assert_eq!(recorded_millis("2026-11-16T00:00:00Z abc\n"), None);
        assert_eq!(stage_line("s", "ran", Some(1250)), "stage s ran 1.250");
        assert_eq!(stage_line("s", "ran", Some(7)), "stage s ran 0.007");
        assert_eq!(stage_line("s", "hit", None), "stage s hit -");
    }

    // FIRST IN, FIRST OUT, AND EXACTLY THE EXCESS (CLOUD-2784): an off-by-one
    // keeps 33 or drops 2, newest-first drops the receipt just written, and an
    // unstable tie drops whichever the directory listed first.
    #[test]
    fn evict_drops_only_the_oldest_past_the_cap() {
        let stamp = |n: usize| format!("2026-11-18T10:{:02}:{:02}Z", n / 60, n % 60);
        let entries: Vec<(String, String)> = (0..33)
            .rev()
            .map(|n| (format!("r{n:02}"), stamp(n)))
            .collect();
        assert_eq!(super::evict(&entries, 32), vec!["r00".to_owned()]);
        assert!(
            super::evict(&entries[..32], 32).is_empty(),
            "at the cap, none"
        );

        let tied = vec![
            ("b".to_owned(), stamp(0)),
            ("a".to_owned(), stamp(0)),
            ("c".to_owned(), stamp(5)),
        ];
        assert_eq!(super::evict(&tied, 2), vec!["a".to_owned()]);
        assert_eq!(super::evict(&tied, 1), vec!["a".to_owned(), "b".to_owned()]);
    }

    // EACH RULE OF THE TRACE LINT, ONE PATH APIECE (CLOUD-2784): dropping any
    // clause turns its path undeclared, or declares the one that is not.
    #[test]
    fn only_an_undeclared_unignored_worktree_read_is_undeclared() {
        let root = std::path::Path::new("/repo");
        let touched: Vec<std::path::PathBuf> = [
            "/repo/a/x.rs",         // under a declared pathspec
            "/repo",                // the root
            "/repo/deep",           // an ancestor of a declared pathspec
            "/repo/.git/HEAD",      // the git dir
            "/usr/lib/libc.so",     // outside the worktree
            "/repo/target/debug/t", // ignored, by its ancestor
            "/repo/b",              // undeclared
            "/repo/c/missing",      // undeclared, a probe that found nothing
            "/repo/b",              // repeated
        ]
        .map(std::path::PathBuf::from)
        .to_vec();
        let inputs = vec!["a".to_owned(), "deep/er/file".to_owned()];
        let mut asked = Vec::new();
        let mut ignored = |path: &str| {
            asked.push(path.to_owned());
            path == "target"
        };
        let found = super::undeclared(root, &inputs, &touched, &mut ignored);
        assert_eq!(found, vec!["b".to_owned(), "c/missing".to_owned()]);
        assert!(
            !asked.iter().any(|path| path == "target/debug/t"),
            "an ignored ancestor answers for everything beneath it: {asked:?}"
        );
    }

    #[test]
    fn the_whole_tree_declared_leaves_nothing_undeclared() {
        let touched = vec![std::path::PathBuf::from("/repo/anything")];
        let found = super::undeclared(
            std::path::Path::new("/repo"),
            &[".".to_owned()],
            &touched,
            &mut |_| false,
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn an_ancestor_is_the_literal_part_of_a_spec_beneath_it() {
        assert!(super::ancestor_of("crates", "crates/batten/src"));
        assert!(super::ancestor_of("crates", "crates/*/src"));
        assert!(!super::ancestor_of("crate", "crates/batten"));
        assert!(!super::ancestor_of("crates/batten", "crates"));
    }

    // TODAY'S BYTES, LITERALLY (CLOUD-2785): before rows could schedule, the
    // key's row line was the whole row serialized, and this is that string for
    // this row. A field added to the projection, or one leaking from `Step`,
    // changes it and re-runs every step on its next lap.
    #[test]
    fn only_id_inputs_and_tools_are_key_material() {
        let keyed = |run: Option<&str>, group: Option<&str>| crate::step_table::Step {
            id: String::from("s"),
            inputs: Some(vec![String::from("a")]),
            tools: Some(vec![vec![String::from("t"), String::from("--version")]]),
            run: run.map(|word| vec![word.to_owned()]),
            group: group.map(str::to_owned),
            depends_on: group.map_or_else(Vec::new, |_| vec![String::from("x")]),
            verdict: group.map(|_| crate::step_table::Verdict::Exit),
            journal: group.map(|_| crate::step_table::Journal::Nextest),
        };
        let today = r#"row {"id":"s","inputs":["a"],"tools":[["t","--version"]]}"#;
        assert_eq!(super::row_line(&keyed(None, None)).as_deref(), Some(today));
        assert_eq!(
            super::row_line(&keyed(Some("go"), Some("g"))).as_deref(),
            Some(today)
        );
        let mut node = keyed(Some("go"), Some("g"));
        node.inputs = None;
        node.tools = None;
        assert_eq!(
            super::row_line(&node),
            None,
            "a schedule-only node keys nothing"
        );
    }

    #[test]
    fn a_receipts_stamp_is_its_first_field() {
        assert_eq!(
            super::receipt_stamp("2026-11-18T10:00:00Z 12ms abc\n"),
            "2026-11-18T10:00:00Z"
        );
        assert_eq!(super::receipt_stamp(""), "");
    }

    #[test]
    fn every_miss_says_miss_first_and_only_a_hit_says_hit() {
        for answer in [Answer::Off, Answer::NoKey, Answer::Miss(key_of("x"))] {
            assert!(answer.line("a").starts_with("miss"), "{answer:?}");
            assert!(!answer.is_hit(), "{answer:?}");
        }
        assert!(Answer::Hit(key_of("x")).is_hit());
    }

    /// Fails by: a tool that exits zero saying nothing, or fails while saying
    /// something, still keying a receipt the toolchain never vouched for.
    #[test]
    fn a_tool_must_both_exit_zero_and_say_something() {
        let root = crate::scratch::scratch("step-material");
        crate::gitwrite::init_on_main(&root).unwrap();
        std::fs::write(root.join("input"), "x\n").unwrap();
        crate::gitwrite::commit_paths(&root, &[String::from("input")], "input").unwrap();
        let row = |tool: &[&str]| Step {
            id: String::from("s"),
            inputs: Some(vec![String::from("input")]),
            tools: Some(vec![tool.iter().map(|word| (*word).to_owned()).collect()]),
            run: None,
            group: None,
            depends_on: Vec::new(),
            verdict: None,
            journal: None,
        };
        // The platform's own shell spells each tool: one that answers, one
        // that exits zero saying nothing, and one that answers and fails.
        let (answers, silent, fails): (&[&str], &[&str], &[&str]) = if cfg!(windows) {
            (
                &["cmd", "/C", "echo v1"],
                &["cmd", "/C", "rem"],
                &["cmd", "/C", "echo v1& exit 1"],
            )
        } else {
            (&["echo", "v1"], &["true"], &["sh", "-c", "echo v1; exit 1"])
        };
        assert!(
            material(&root, &row(answers), &[], None).is_some(),
            "the premise: a tool that answers keys the step"
        );
        assert_eq!(material(&root, &row(silent), &[], None), None);
        assert_eq!(material(&root, &row(fails), &[], None), None);
    }

    /// A row read as the committed table would read it, so a field added to
    /// [`Step`] cannot break the env cases below.
    fn env_row(id: &str) -> Step {
        toml::from_str(&format!(
            "id = \"{id}\"\ninputs = [\"input\"]\ntools = [[\"echo\", \"v1\"]]\n"
        ))
        .unwrap()
    }

    /// `vars` as the process environment iterator [`env_lines`] reads.
    fn env_vars(
        pairs: &[(&str, &str)],
    ) -> impl Iterator<Item = (std::ffi::OsString, std::ffi::OsString)> {
        pairs
            .iter()
            .map(|(k, v)| (std::ffi::OsString::from(k), std::ffi::OsString::from(v)))
            .collect::<Vec<_>>()
            .into_iter()
    }

    // TODAY'S KEY, LITERALLY (CLOUD-2786): captured before the env lines
    // existed. A row whose `tools` carry no `batten step env` entry keys
    // exactly as it did, so no receipt is lost to the declaration's arrival.
    // The literal was captured on unix, where the index mode it hashes is
    // `100644`; elsewhere the absence of env lines is the whole assertion.
    #[test]
    fn a_row_without_env_keys_as_before() {
        let root = crate::scratch::scratch("step-env-pin");
        crate::gitwrite::init_on_main(&root).unwrap();
        std::fs::write(root.join("input"), "x\n").unwrap();
        crate::gitwrite::commit_paths(&root, &[String::from("input")], "input").unwrap();
        let row = env_row("cloud-2786-pin");
        let material = material(&root, &row, &[], None).unwrap();
        assert!(!material.contains("\nenv "), "{material}");
        if cfg!(unix) {
            assert_eq!(
                key_of(&material),
                "aedfe39d1eaff13ff2e4b62d52458580c648174bf67fc2b392c9d30f3901c162",
                "{material}"
            );
        }
    }

    /// Fails by: a declared variable's value, a newly set declared variable,
    /// or a declaration matching nothing leaving the key unmoved.
    #[test]
    fn a_declared_env_value_moves_the_key() {
        let declared = crate::mutate::resume::declare(
            vec![
                String::from("DATABASE_URL"),
                String::from("APP_*"),
                String::from("ABSENT"),
            ],
            Vec::new(),
        )
        .unwrap();
        let lines = |pairs: &[(&str, &str)]| env_lines(&declared, env_vars(pairs)).unwrap();
        let base = lines(&[("DATABASE_URL", "a"), ("APP_MODE", "x")]);
        assert_eq!(
            base,
            vec![
                String::from(r#"env "ABSENT" none"#),
                String::from(r#"env "APP_MODE=x""#),
                String::from(r#"env "DATABASE_URL=a""#),
            ]
        );
        assert_ne!(base, lines(&[("DATABASE_URL", "b"), ("APP_MODE", "x")]));
        assert_ne!(base, lines(&[("DATABASE_URL", "a"), ("APP_MODE", "y")]));
        assert_ne!(
            base,
            lines(&[("DATABASE_URL", "a"), ("APP_MODE", "x"), ("APP_NEW", "1")])
        );
        assert_ne!(
            base,
            lines(&[("DATABASE_URL", "a"), ("APP_MODE", "x"), ("ABSENT", "")]),
            "a declaration that starts matching moves the key"
        );
    }

    /// Fails by: an excluded per-run variable, or an undeclared one, moving
    /// the key (every run a miss), or an exclusion read as a prefix.
    #[test]
    fn an_excluded_variable_does_not_move_the_key() {
        let declared = crate::mutate::resume::declare(
            vec![String::from("APP_*")],
            vec![String::from("APP_PID")],
        )
        .unwrap();
        let lines = |pairs: &[(&str, &str)]| env_lines(&declared, env_vars(pairs)).unwrap();
        let base = lines(&[("APP_MODE", "x"), ("APP_PID", "1"), ("TERM", "a")]);
        assert_eq!(
            base,
            lines(&[("APP_MODE", "x"), ("APP_PID", "2"), ("TERM", "b")])
        );
        assert_eq!(base, lines(&[("APP_MODE", "x")]));
        assert_ne!(
            base,
            lines(&[("APP_MODE", "x"), ("APP_PID2", "1")]),
            "an exclusion names one variable, never a prefix"
        );
    }

    /// Fails by: a `batten step env` tool line spawned (a process per lap, and
    /// the released engine answering a verb it lacks with no key), answered
    /// with anything but [`env_lines`]' own lines, or a malformed line keyed
    /// rather than refused. `step env` and the cache share the lines, so the
    /// verb prints exactly what the key hashes.
    #[test]
    fn the_env_line_is_answered_in_process() {
        let root = crate::scratch::scratch("step-env-in-process");
        let line = |words: &[&str]| -> Vec<String> {
            crate::mutate::resume::ENV
                .iter()
                .chain(words)
                .map(|word| (*word).to_owned())
                .collect()
        };
        // A name no environment sets: its line is `none`, whatever runs this.
        let absent = "BATTEN_CLOUD_2786_NEVER_SET";
        assert_eq!(
            tool_said(&root, &line(&["--", absent])),
            Some((0, format!(r#"env "{absent}" none"#)))
        );
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_env(&[], &[absent.to_owned()], &mut out, &mut err).unwrap();
        assert_eq!(code, ExitCode::Success);
        assert_eq!(
            String::from_utf8(out).unwrap(),
            format!("env \"{absent}\" none\n")
        );
        for malformed in [
            &["--", "lower"][..],
            &[absent][..],
            &["--"][..],
            &["--bogus", "--", absent][..],
        ] {
            assert_eq!(
                tool_said(&root, &line(malformed)),
                Some((1, String::new())),
                "{malformed:?}"
            );
        }
        let mut out = Vec::new();
        let code = run_env(
            &[String::from("A*")],
            &[absent.to_owned()],
            &mut out,
            &mut err,
        )
        .unwrap();
        assert_eq!(
            code,
            ExitCode::Usage,
            "an exclusion is a name, never a pattern"
        );
        assert!(out.is_empty());
    }

    /// Fails by: the engine's own digest line spawned rather than answered
    /// in-process (a build and a policy load per lap), answered with anything
    /// but `--inputs-digest`'s own digest, or a key that holds when the
    /// out-of-tree state it digests moves.
    #[test]
    fn the_inputs_digest_line_is_answered_in_process() {
        let root = crate::scratch::scratch("step-inputs-digest");
        crate::gitwrite::init_on_main(&root).unwrap();
        std::fs::write(root.join("input"), "x\n").unwrap();
        crate::gitwrite::commit_paths(&root, &[String::from("input")], "input").unwrap();
        let native: Vec<String> = INPUTS_DIGEST
            .iter()
            .map(|word| (*word).to_owned())
            .collect();
        let digest = tree_inputs_digest_in(&root).unwrap();
        assert_eq!(tool_said(&root, &native), Some((0, digest.clone())));
        let row = Step {
            id: String::from("s"),
            inputs: Some(vec![String::from("input")]),
            tools: Some(vec![native]),
            run: None,
            group: None,
            depends_on: Vec::new(),
            verdict: None,
            journal: None,
        };
        let held = material(&root, &row, &[], None).expect("the line keys the step");
        assert!(held.contains(&digest), "keyed on the in-process digest");
        std::fs::write(
            root.join(crate::resolve::LOCAL_CONFIG_FILE),
            "version = 1\n",
        )
        .unwrap();
        assert_ne!(
            material(&root, &row, &[], None),
            Some(held),
            "a moved local config moves the key"
        );
    }

    /// A linear history and the ids of its first three commits: `r[0]` (src
    /// x, docs 1), `r[1]` (docs 2 only), `r[2]` (src y), then a HEAD commit on
    /// top, so each one's merge base with HEAD is that commit itself.
    fn based(name: &str) -> (std::path::PathBuf, Vec<String>) {
        let root = crate::scratch::scratch(name);
        crate::gitwrite::init_on_main(&root).unwrap();
        std::fs::create_dir_all(root.join("src")).unwrap();
        std::fs::create_dir_all(root.join("docs")).unwrap();
        let paths = [String::from("src/lib.rs"), String::from("docs/a.md")];
        let mark = |file: &str, text: &str| {
            std::fs::write(root.join(file), text).unwrap();
            crate::gitwrite::commit_paths(&root, &paths, file).unwrap();
            crate::git::head_commit(&root).unwrap()
        };
        std::fs::write(root.join("docs/a.md"), "1\n").unwrap();
        let marked = vec![
            mark("src/lib.rs", "x\n"),
            mark("docs/a.md", "2\n"),
            mark("src/lib.rs", "y\n"),
        ];
        mark("docs/a.md", "3\n");
        (root, marked)
    }

    fn ask(reference: &str, ref_env: Option<&str>, paths: &[&str]) -> BaseAsk {
        BaseAsk {
            reference: reference.to_owned(),
            ref_env: ref_env.map(str::to_owned),
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
        }
    }

    const NO_VAR: &dyn Fn(&str) -> Option<String> = &|_| None;

    /// Fails by: a base half keyed on the merge base's COMMIT id, which moves
    /// with a trunk commit touching none of the declared paths (CLOUD-2787).
    #[test]
    fn a_base_commit_moving_with_the_same_trees_keeps_the_key() {
        let (root, r) = based("step-base-same-trees");
        let one = base_said(&root, &ask(r[0].as_str(), None, &["src"]), NO_VAR).unwrap();
        assert_eq!(
            base_said(&root, &ask(r[1].as_str(), None, &["src"]), NO_VAR),
            Some(one.clone()),
            "r2 moved only docs"
        );
        assert!(one.starts_with("base src "), "{one}");
        assert!(!one.contains(r[0].as_str()), "no commit id in the lines");
    }

    /// Fails by: a base half blind to a declared path's content, or one that
    /// drops a missing path rather than keying it `absent`.
    #[test]
    fn a_base_path_changing_moves_the_key() {
        let (root, r) = based("step-base-path-moves");
        let one = base_said(&root, &ask(r[0].as_str(), None, &["src"]), NO_VAR).unwrap();
        assert_ne!(
            base_said(&root, &ask(r[2].as_str(), None, &["src"]), NO_VAR),
            Some(one)
        );
        assert_eq!(
            base_said(&root, &ask(r[0].as_str(), None, &["nowhere"]), NO_VAR).as_deref(),
            Some("base nowhere absent")
        );
        assert_eq!(
            base_said(&root, &ask("no-such-ref", None, &["src"]), NO_VAR),
            None,
            "an unresolvable ref is no key"
        );
    }

    /// Fails by: `ref_env` ignored, read when set but empty, or read when the
    /// row names no variable.
    #[test]
    fn a_set_ref_env_replaces_the_ref() {
        let (root, r) = based("step-base-ref-env");
        let set = |name: &str| (name == "BASE_VAR").then(|| r[2].clone());
        let empty = |_: &str| Some(String::new());
        let at_r3 = base_said(&root, &ask(r[2].as_str(), None, &["src"]), NO_VAR);
        let at_r1 = base_said(&root, &ask(r[0].as_str(), None, &["src"]), NO_VAR);
        assert_ne!(at_r1, at_r3, "the premise");
        assert_eq!(
            base_said(&root, &ask(r[0].as_str(), Some("BASE_VAR"), &["src"]), &set),
            at_r3
        );
        assert_eq!(
            base_said(
                &root,
                &ask(r[0].as_str(), Some("BASE_VAR"), &["src"]),
                &empty
            ),
            at_r1
        );
        assert_eq!(
            base_said(&root, &ask(r[0].as_str(), None, &["src"]), &set),
            at_r1
        );
    }

    /// Fails by: the tool line spawned (a process per lap) or answered by a
    /// parse other than the canonical spelling.
    #[test]
    fn the_base_line_is_answered_in_process() {
        let (root, r) = based("step-base-in-process");
        let line = |words: &[&str]| -> Vec<String> {
            BASE.iter()
                .chain(words)
                .map(|word| (*word).to_owned())
                .collect()
        };
        let said = base_said(&root, &ask(r[0].as_str(), None, &["src", "docs"]), NO_VAR).unwrap();
        assert_eq!(
            tool_said(&root, &line(&["--ref", r[0].as_str(), "--", "src", "docs"])),
            Some((0, said))
        );
        assert_eq!(
            tool_said(&root, &line(&["--ref", r[0].as_str()])),
            Some((1, String::new()))
        );
        assert_eq!(
            tool_said(&root, &line(&["--bogus", "--", "src"])),
            Some((1, String::new()))
        );
    }

    /// The words of a `step base` line after [`BASE`].
    fn base_words(words: &[&str]) -> Vec<String> {
        words.iter().map(|word| (*word).to_owned()).collect()
    }

    /// CLOUD-2787's `a_base_without_inputs_is_refused`, under the tool-line
    /// design: a `step base` line naming no path is no declaration, so the row
    /// keys nothing and runs, and the verb refuses it as a usage error.
    ///
    /// Fails by: a base of no paths read as a declaration, which keys an empty
    /// base and hits across every trunk move.
    #[test]
    fn a_base_without_inputs_is_refused() {
        assert_eq!(base_ask(&base_words(&["--ref", "origin/main", "--"])), None);
        assert!(base_ask(&base_words(&["--ref", "origin/main", "--", "src"])).is_some());
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_base("origin/main", None, &[], &mut out, &mut err).unwrap(),
            ExitCode::Usage
        );
    }

    /// CLOUD-2787's `a_base_with_an_empty_ref_is_refused`, under the tool-line
    /// design.
    ///
    /// Fails by: an empty ref read as a declaration, which resolves nothing and
    /// would key whatever an empty revision happens to answer.
    #[test]
    fn a_base_with_an_empty_ref_is_refused() {
        assert_eq!(base_ask(&base_words(&["--ref", "", "--", "src"])), None);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_base("", None, &[String::from("src")], &mut out, &mut err).unwrap(),
            ExitCode::Usage
        );
    }
}
