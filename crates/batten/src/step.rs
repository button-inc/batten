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

/// The keyed family a passed step's receipt lives in: one record per step.
pub const RECEIPTS: &str = "steps";

/// The keyed family `check` files the key under that a `record` must match.
pub const PENDING: &str = "step-pending";

/// The variable that switches the cache off locally, so a measurement can see
/// the uncached cost.
pub const BYPASS: &str = "BATTEN_STEP_RECEIPT_BYPASS";

/// The variable a supervising task exports its registry pid in (CLOUD-425).
const TASK_PID: &str = "BATTEN_TASK_PID";

/// How much of the key a line shows. A pointer, never the whole digest.
const SHOWN: usize = 12;

// The cache's mutation rows, carried from the retired task's six and widened by
// the three the composed `run` arm adds. Each breaks one clause a receipt's
// soundness rests on, and each is caught by the compiled-binary case it names.
//MUTANT-SUITE crates/batten/tests/it/step_receipt.rs
//MUTANT hit-without-key-match|s@^    if stored.as_deref() == Some(key.as_str()) {$@    if true {@|a_changed_input_file_misses
//MUTANT args-not-keyed|s@^    lines.extend(args.iter().map(.arg. format!("arg {}", quoted(arg))));$@    let _ = args;@|a_changed_argument_misses
//MUTANT command-not-keyed|s@^        lines.push(format!("command {}", serde_json::to_string(command).ok()?));$@        let _ = command;@|a_changed_command_misses
//MUTANT tools-not-keyed|s@^            quoted(said)$@            quoted("")@|a_changed_tool_version_misses
//MUTANT dirty-index-trusted|s@^        if !clean {$@        if clean == !clean {@|unstaged_divergence_is_no_key
//MUTANT weld-unchecked|s@^    if key.as_deref() != Some(expected.as_str()) {$@    if key.is_none() {@|inputs_changing_while_the_step_ran_refuse_the_record
//MUTANT ci-caches|s@^    if bypassed() {$@    if false {@|under_ci_the_cache_neither_hits_nor_records
//MUTANT failure-recorded|s@^    let passed = matches!(ran, Ok(ExitCode::Success));$@    let passed = true;@|a_failing_command_passes_its_code_through_and_records_nothing
//MUTANT hit-runs-anyway|s@^    if answer.is_hit() {$@    if false {@|a_hit_does_not_run_the_command
// And the three the review added: the row as key material, the table read from
// the keyed tree alone, and no key running the step rather than skipping it.
//MUTANT row-not-keyed|s@^    lines.push(format!("row {}", serde_json::to_string(row).ok()?));$@    let _ = row;@|an_edited_row_is_a_miss
//MUTANT config-source-honoured|s@&Overrides::default()).ok()?;$@\&{ let mut o = Overrides::default(); o.config_in = std::env::var("BATTEN_CONFIG_IN").ok(); o }).ok()?;@|a_config_source_override_does_not_reach_the_step_table
//MUTANT no-key-skips|s@^    if answer.is_hit() {$@    if !matches!(answer, Answer::Miss(_)) {@|an_authority_that_will_not_load_still_runs_the_step
//MUTANT step-run-drops-child-stderr|s@^    settings.tee = true;$@    settings.tee = false;@|a_failing_step_shows_the_commands_own_output
//MUTANT record-refusal-fails-step|s@^        let _ = record(step, args, Some(command), &mut recorded, &mut refused);$@        if !matches!(record(step, args, Some(command), \&mut recorded, \&mut refused), Ok(ExitCode::Success)) { return Ok(ExitCode::Violation); }@|a_passing_step_whose_record_refuses_stays_green

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
    const fn is_hit(&self) -> bool {
        matches!(self, Answer::Hit(_))
    }
}

/// The first [`SHOWN`] characters of a key.
fn shown(key: &str) -> &str {
    key.get(..SHOWN).unwrap_or(key)
}

/// Whether the cache is switched off here.
fn bypassed() -> bool {
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

/// Everything the key hashes, or `None` where any part cannot be read.
///
/// Each component is a line of its own and every free-form value is JSON-quoted,
/// so no tool's output can impersonate the lines that follow it.
fn material(row: &Step, args: &[String], command: Option<&[String]>) -> Option<String> {
    let root = Path::new(".");
    let mut lines: Vec<String> = vec![format!("step {}", serde_json::to_string(&row.id).ok()?)];
    // The declaration itself: a receipt earned under one `inputs`/`tools` set
    // never answers under a narrower one.
    lines.push(format!("row {}", serde_json::to_string(row).ok()?));
    lines.extend(args.iter().map(|arg| format!("arg {}", quoted(arg))));
    if let Some(command) = command {
        lines.push(format!("command {}", serde_json::to_string(command).ok()?));
    }
    for tool in &row.tools {
        let (code, said) =
            crate::exec::piped_argv(root, tool, "", crate::exec::Diagnostics::Drop, &[])?;
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
    let facts = crate::git::index_facts(root, &row.inputs).ok()?;
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
        .and_then(|row| material(row, args, command))
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
    let stored = read_key(git_dir.as_deref(), RECEIPTS, step);
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
        .and_then(|row| material(row, args, command))
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
    let receipt = format!(
        "{} {expected}\n",
        crate::receipt::rfc3339_utc(crate::boundary_epoch())
    );
    let written = git_dir
        .as_deref()
        .map(|git_dir| crate::record::keyed_write(git_dir, RECEIPTS, step, &receipt));
    if !matches!(written, Some(Ok(()))) {
        writeln!(
            err,
            "step record: {step} — could not write the receipt; the next run re-derives"
        )?;
        return Ok(ExitCode::Internal);
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
    record(step, args, None, out, err)
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
    if answer.is_hit() {
        return Ok(ExitCode::Success);
    }
    // TEED, NOT ONLY CAPTURED (CLOUD-2091). `exec::run`'s default stores the
    // child's bytes and prints none of them, which is right for `batten exec` and
    // wrong here: a step is a gate whose reader is a log, and on a CI runner the
    // capture store dies with the job. A failing `test:cargo` then said only
    // `ERROR task failed`, with no case named anywhere a person could read it.
    let mut settings = crate::exec::ExecConfig::DEFAULT;
    settings.tee = true;
    let ran = crate::exec::run_with(command, &[], &settings, &mut std::io::sink());
    let passed = matches!(ran, Ok(ExitCode::Success));
    if passed && matches!(answer, Answer::Miss(_)) {
        // A record that refuses or fails here — the inputs moved while the
        // command ran, the store would not take the write — costs the next run
        // a re-derive and says so on stderr. Its `Result` is discarded, never
        // `?`-propagated: a passing step stays a passing step.
        let mut recorded = Vec::new();
        let mut refused = Vec::new();
        let _ = record(step, args, Some(command), &mut recorded, &mut refused);
        let _ = err.write_all(&recorded);
        let _ = err.write_all(&refused);
    }
    ran
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

    #[test]
    fn every_miss_says_miss_first_and_only_a_hit_says_hit() {
        for answer in [Answer::Off, Answer::NoKey, Answer::Miss(key_of("x"))] {
            assert!(answer.line("a").starts_with("miss"), "{answer:?}");
            assert!(!answer.is_hit(), "{answer:?}");
        }
        assert!(Answer::Hit(key_of("x")).is_hit());
    }
}
