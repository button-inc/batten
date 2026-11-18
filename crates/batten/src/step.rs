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
//! verb's, passed through unchanged), and record only on a zero exit. A record
//! that refuses after a passing run is an economy lost, never the step's verdict.
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
    ["CI", BYPASS]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
}

/// Say which step a supervising task is on (CLOUD-425). Best-effort:
/// bookkeeping never changes a verdict, and a pid nothing registered is a no-op.
fn announce(step: &str) {
    let Some(pid) = std::env::var(TASK_PID).ok().filter(|pid| !pid.is_empty()) else {
        return;
    };
    let Ok(git_dir) = crate::git::git_dir(Path::new(".")) else {
        return;
    };
    crate::task::push(
        &git_dir,
        &pid,
        crate::task::Signal::Phase,
        step,
        crate::boundary_epoch(),
    );
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
/// ([`crate::tree_inputs_digest_in`]).
pub const INPUTS_DIGEST: [&str; 5] = ["batten", "enforce", "--half", "tree", "--inputs-digest"];

/// What `tool` says run in `root`, as its exit code and stdout: answered
/// in-process for [`INPUTS_DIGEST`] (a digest that cannot be taken is a
/// non-zero code, so no key), spawned through the placed boundary for every
/// other line. `None` where it could not be spawned.
fn tool_said(root: &Path, tool: &[String]) -> Option<(i32, String)> {
    if tool.iter().map(String::as_str).eq(INPUTS_DIGEST) {
        return Some(
            crate::tree_inputs_digest_in(root)
                .map_or_else(|_| (1, String::new()), |said| (0, said)),
        );
    }
    crate::exec::piped_argv(root, tool, "", crate::exec::Diagnostics::Drop, &[])
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
    let stored = git_dir
        .as_deref()
        .and_then(|git_dir| crate::record::keyed_group_read(git_dir, RECEIPTS, step, &key))
        .and_then(|value| stored_key(&value));
    if stored.as_deref() == Some(key.as_str()) {
        return Answer::Hit(key);
    }
    // The pending key is what a later `record` must match. A store that will not
    // take it costs the economy, never the verdict: `record` then refuses.
    if let Some(git_dir) = &git_dir {
        let _ = crate::record::keyed_write(git_dir, PENDING, step, &format!("{key}\n"));
    }
    Answer::Miss(key)
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
    let stamp = crate::receipt::rfc3339_utc(crate::boundary_epoch());
    let receipt = elapsed.map_or_else(
        || format!("{stamp} {expected}\n"),
        |elapsed| format!("{stamp} {}ms {expected}\n", elapsed.as_millis()),
    );
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
    writeln!(said, "step record: {step} — recorded {}", shown(&expected))?;
    Ok(ExitCode::Success)
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
        return Ok(ExitCode::Success);
    }
    let started = std::time::Instant::now();
    // TEED, NOT ONLY CAPTURED (CLOUD-2091). `exec::run`'s default stores the
    // child's bytes and prints none of them, which is right for `batten exec` and
    // wrong here: a step is a gate whose reader is a log, and on a CI runner the
    // capture store dies with the job. A failing `test:cargo` then said only
    // `ERROR task failed`, with no case named anywhere a person could read it.
    let mut settings = crate::exec::ExecConfig::DEFAULT;
    settings.tee = true;
    // A MISS KEEPS WHAT IT FINISHES, CASE BY CASE, when the command is a
    // nextest run (CLOUD-2772): a stopped run resumes rather than re-running
    // every case it passed. Keyed by the command's own argv, never a config key,
    // so the released engine reading the authority meets nothing new. The
    // receipt's key stays the declared command's; a journal that cannot be set
    // up runs the command as declared, because the journal is an economy and
    // the step's verdict is the command's alone.
    // BY THE ROW, NEVER BY THE ARGV (CLOUD-2785): `journal = "nextest"`.
    let journaled = declared(step)
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
    let traced = matches!(answer, Answer::Miss(_))
        .then(crate::mutate::trace::tracer)
        .flatten()
        .and_then(|strace| Some((strace, trace_file(step)?)));
    let spawned: Vec<String> = match (&traced, running.split_first()) {
        (Some((strace, file)), Some((program, rest))) => std::iter::once(strace.clone())
            .chain(crate::mutate::trace::trace_args(file, program, rest))
            .collect(),
        _ => running.to_vec(),
    };
    let ran = crate::exec::run_with(&spawned, &[], &settings, &mut std::io::sink());
    // THE RUN'S DEPENDENCY PASSES OUTLIVE IT only over a tree that stood for
    // the whole of it; an economy either way, so its failure is swallowed.
    if let Some((_, root)) = &journaled {
        let _ = crate::mutate::resume::promote(root);
    }
    let elapsed = started.elapsed();
    let passed = matches!(ran, Ok(ExitCode::Success));
    if passed && let Some((_, file)) = &traced {
        match lint_trace(step, file) {
            Linted::Undeclared(count, listing) => {
                let _ = writeln!(
                    err,
                    "step run: {step} read {count} path(s) outside its inputs; read {}",
                    listing.display()
                );
                return Ok(ExitCode::Violation);
            }
            // The row no longer reads (the command moved the authority): the
            // record below recomputes the key and refuses on its own words.
            Linted::Declared | Linted::RowUnread => {}
            Linted::Unread => {
                // A trace that cannot be read whole proves nothing about the
                // declaration, so no receipt: the step's own verdict stands.
                let _ = writeln!(
                    err,
                    "step run: {step} — its trace could not be read whole; not recording"
                );
                return ran;
            }
        }
    }
    if passed && matches!(answer, Answer::Miss(_)) {
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
    let millis = u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX);
    let _ = writeln!(err, "{}", stage_line(step, "ran", Some(millis)));
    ran
}

/// Where a step's traced run writes its trace: a file directly under the git
/// dir, which exists, so nothing is created here, and `strace -o` truncates it,
/// so nothing is removed. `None` where the git dir cannot be found, which runs
/// the step untraced.
fn trace_file(step: &str) -> Option<std::path::PathBuf> {
    let git_dir = crate::git::git_dir(Path::new(".")).ok()?;
    Some(git_dir.join(format!(
        "{TRACES}-{}.trace",
        crate::tools::digest(step.as_bytes())
    )))
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
    let Some(touched) = crate::mutate::trace::await_trace(file)
        .as_deref()
        .and_then(|text| crate::mutate::trace::touched(text, cwd.as_deref()))
    else {
        return Linted::Unread;
    };
    let mut cache = BTreeMap::new();
    let mut ignored = |path: &str| {
        *cache
            .entry(path.to_owned())
            .or_insert_with(|| crate::git::check_ignore(&root, path).unwrap_or(false))
    };
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

/// `batten step graph run <group> [--jobs N]` (CLOUD-2785): every row of
/// `group`, each as a child process from its `run` argv, a row starting only
/// once every `depends_on` exited 0, at most `jobs` at once.
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
pub fn run_graph(group: &str, jobs: Option<&str>, err: &mut dyn Write) -> Result<ExitCode> {
    let jobs = match jobs.map(str::parse::<std::num::NonZeroUsize>) {
        None => None,
        Some(Ok(jobs)) => Some(jobs),
        Some(Err(_)) => {
            writeln!(err, "step graph: --jobs takes a positive integer")?;
            return Ok(ExitCode::Usage);
        }
    };
    let rows: Vec<Step> = match crate::resolve::committed(Path::new("."), &Overrides::default()) {
        Ok(config) => config
            .steps
            .into_iter()
            .filter(|row| row.group.as_deref() == Some(group))
            .collect(),
        Err(error) => {
            writeln!(err, "step graph: the step table did not load: {error}")?;
            return Ok(ExitCode::Usage);
        }
    };
    if rows.is_empty() {
        writeln!(err, "step graph: no [[step]] row is in group {group}")?;
        return Ok(ExitCode::Usage);
    }
    let bound = jobs.map_or(usize::MAX, std::num::NonZeroUsize::get);
    let outcome = schedule(&rows, bound, &|row: &Step| {
        let mut settings = crate::exec::ExecConfig::DEFAULT;
        settings.tee = true;
        let argv = row.run.clone().unwrap_or_default();
        // A NON-ZERO CHILD ARRIVES AS A `Passthrough` carrying its own code,
        // which may sit outside the §7 table; anything else is a spawn that
        // never decided, which is internal.
        match crate::exec::run_with(&argv, &[], &settings, &mut std::io::sink()) {
            Ok(code) => code.code(),
            Err(error) => error
                .downcast_ref::<crate::error::Passthrough>()
                .map_or(ExitCode::Internal.code(), |carried| carried.0),
        }
    });
    for line in &outcome.lines {
        writeln!(err, "step graph: {line}")?;
    }
    writeln!(
        err,
        "step graph: {group} peak {} of {}",
        outcome.peak,
        jobs.map_or_else(|| String::from("unbounded"), |jobs| jobs.to_string())
    )?;
    if outcome.worst == 0 {
        return Ok(ExitCode::Success);
    }
    ExitCode::from_code(outcome.worst)
        .map_or_else(|| Err(crate::error::Passthrough::raise(outcome.worst)), Ok)
}

/// What a scheduled graph did: a pointer line per node, the most rows that ran
/// at once, and the worst code.
struct Scheduled {
    lines: Vec<String>,
    peak: usize,
    worst: i32,
}

/// Run `rows` as a dependency graph with at most `bound` at once, each through
/// `run`. Pure over `run`, so the order, the bound and the skips are testable
/// without a process.
fn schedule(rows: &[Step], bound: usize, run: &(dyn Fn(&Step) -> i32 + Sync)) -> Scheduled {
    let mut done: BTreeMap<&str, i32> = BTreeMap::new();
    let mut waiting: Vec<&Step> = rows.iter().collect();
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
                done.insert(row.id.as_str(), ExitCode::Internal.code());
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
            done.insert(id, code);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

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
        let digest = crate::tree_inputs_digest_in(&root).unwrap();
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
}
