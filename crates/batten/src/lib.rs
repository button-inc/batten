//! Batten is a repo-agnostic policy engine.
//!
//! It gates what gets written, proves what was verified, and refuses to let
//! unlanded work appear finished — enforcing one repository's policy consistently
//! at the pre-commit layer, in CI, and at an agent's tool call.
//!
//! This crate exposes the library surface ([`run`]) that the `batten` binary is a
//! thin wrapper around. Keeping the logic in the library keeps it testable and
//! keeps the binary's `main` trivial.

pub mod action;
pub mod admission;
pub mod advisory;
pub mod agent;
pub mod attribution;
pub mod baseline;
pub mod bot;
pub mod brief;
pub mod budget;
pub mod bypass;
pub mod capture;
/// Declared reductions over responses the agent already captured.
pub mod captured;
pub mod carry;
pub mod checks_green;
pub mod ci;
pub mod claim;
pub mod cli;
pub mod commit;
pub mod completion;
pub mod config;
pub mod contract;
pub mod decision;
pub mod defects;
pub mod design;
pub mod doctor;
pub mod drain;
pub mod effect;
pub mod emission;
pub mod environment;
pub mod epoch;
pub mod error;
pub mod exec;
pub mod exit;
pub mod facts;
/// Asking the fast-forward bot to land a head, and reading the answer keyed to
/// THIS request rather than to a timestamp (CLOUD-1338).
pub mod fast_forward;
pub mod fetch;
pub mod findings;
pub mod forge;
pub mod git;
pub mod gitwrite;
pub mod handler;
pub mod hook;
pub mod hookcost;
pub mod identity;
pub mod init;
/// Rust call sites, parsed — where a token sits, not merely that it appears.
pub mod invocation;
pub mod journal;
pub mod judge;
/// The landing lap's replay half: advance the base, replay the branch onto it,
/// and record what happened for a module to decide over (CLOUD-1335).
pub mod land;
/// Whether a board column is honest about what git and the forge already did —
/// behind git in one direction, ahead of a declined key in the other
/// (CLOUD-186, CLOUD-1127).
pub mod landed;
/// The landing lease's wire half: ref discovery and a compare-and-swap over a
/// remote ref, spoken as git smart-HTTP over [`fetch`] (CLOUD-1274).
pub mod lease;
pub mod lint;
pub mod markers;
pub mod mcp;
pub mod mint;
pub mod minted;
pub mod mutate;
pub mod output;
pub mod outputs;
/// The in-process patch identity: what a change IS, independent of the commit
/// carrying it and of the host's git configuration.
mod patch;
pub mod pattern;
pub mod perf;
pub mod pinned;
pub mod policy;
pub mod pr_watch;
pub mod preset;
pub mod provision;
pub mod prune;
pub mod race;
pub mod ready;
pub mod receipt;
pub mod record;
pub mod recorder;
pub mod redirect;
pub mod refusal;
pub mod render;
pub mod resolve;
pub mod review;
pub mod rules;
pub mod secrets;
pub mod selfwrite;
/// The API-compatibility gate as a delegated-analyser adapter (CLOUD-1050),
/// carrying a baseline the committed lock can build when the registry can no
/// longer resolve one.
pub mod semver;
pub mod session;
pub mod severity;
pub mod sink;
pub mod spec;
/// Resolved-symbol facts, from a delegated analyser's structured output
/// (CLOUD-760). The first occupant of `Cost::Effect`: resolving it runs a
/// program, which is the classification rather than an accident of it.
pub mod symbols;

pub mod startup;
pub mod state;
pub mod stop;
pub mod store;
pub mod surface;
/// What a long-running task is doing, recorded where it can be read without a log.
pub mod task;
/// The task runner's argv, from a receipt minted outside the mediated call.
pub mod taskset;
/// Third-party tool verdicts, keyed to (tool, pinned version, input digest).
pub mod tools;
pub mod transcript;
pub mod trust;
/// The `use` graph: which module reaches which, resolved through the root's own
/// re-export table.
pub mod uses;
pub mod verbs;
pub mod verdict;
pub mod waiver;
pub mod wiring;
pub mod worktree;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::Result;

pub use cli::{
    AttributionCommand, ChecksCommand, ClaimCommand, Cli, Command, CommitCommand, ConfigCommand,
    DefectsCommand, DesignCommand, GenerateCommand, LandedCommand, LintCommand, OverrideCommand,
    PolicyCommand, PrCommand, ProvisionCommand, ReadyCommand, ReceiptCommand, SemverCommand,
    SingletonCommand, SpecFormat, StateCommand, TaskCommand, WiringCommand, WorktreeCommand,
};
pub use config::Config;
pub use effect::Effect;
pub use error::{Denial, Passthrough, UsageError};
pub use exit::ExitCode;
pub use output::{Mode, Presentation, Verbosity};
pub use refusal::{Fix, Refusal};
pub use resolve::{Contributor, Origin, Overrides, Resolved, Source};
pub use severity::{AdvisoryTier, Mapping, ReportLevel, RuleSeverity};

/// Execute a parsed [`Cli`], writing any data output to `out`, and return the
/// [`ExitCode`] to hand back to the OS.
///
/// Data output goes to `out` (the binary passes stdout) rather than through a
/// `print!`, so the library stays byte-stable and testable and the
/// stdout-is-the-answer split of the output contract is honoured.
///
/// `err` is the **other** channel, and the split is the whole point: nothing a
/// verb writes there can reach the data channel, so a ladder-gated message
/// (CLOUD-42) is structurally incapable of corrupting a `-J` document. `mode`
/// carries the resolved rung, so what gets written there is a decision the
/// binary already made rather than one each verb re-derives.
///
/// # Errors
///
/// Returns an error when a command cannot complete because of an underlying
/// failure (I/O, a missing external tool, or an internal invariant violation).
/// Such errors map to [`ExitCode::Internal`] at the boundary; a *policy
/// violation*, by contrast, is a normal return of [`ExitCode::Violation`].
// THE DISPATCH IS ONE ARM PER VERB, WITH ITS REASON BESIDE IT, and that is the
// point of it rather than a size to be managed — the same argument `spec.rs`'s
// committed row set carries. Splitting the table to satisfy a line count would
// scatter the one place a reader can see the whole surface and what each arm
// answers to, and would put a verb's rationale somewhere its dispatch is not.
//
// `#[expect]` rather than `#[allow]` for `.claude/rules/rust.md`'s reason: it is
// self-cleaning in both directions, so if the table ever shrinks back under the
// ceiling this annotation goes red rather than quietly outliving its cause.
#[expect(
    clippy::too_many_lines,
    reason = "a dispatch table's length is its verb count; splitting it scatters the surface"
)]
pub fn run(cli: Cli, mode: Mode, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let Cli {
        strictness,
        fail_on_warning,
        config_from,
        config_in,
        command,
    } = cli;
    // The flag layer of the §8 precedence chain; every config read in this run
    // resolves through it, so a flag can never apply to one verb and not another.
    let overrides = Overrides {
        strictness,
        fail_on_warning,
        config_from,
        config_in,
    };
    match command {
        // Unreachable in practice: `arg_required_else_help` has clap offer the
        // subcommand listing (a usage error, exit 1) before parse returns. Kept
        // total — the workspace lints forbid panicking on a reachable path.
        None => Ok(ExitCode::Success),
        Some(Command::Check(flags)) => run_check(&flags, mode, &overrides, out, err),
        Some(Command::Enforce(flags)) => run_rules(
            out,
            err,
            mode,
            &overrides,
            rules::run_all_over,
            RunRequest::spawning(flags.json, &flags.rule),
        ),
        Some(Command::Config { command }) => run_config(&command, &overrides, out),
        Some(Command::Spec { format }) => run_spec(format, out),
        Some(Command::ShowAgent { json }) => run_show_agent(json, &overrides, out),
        Some(Command::Doctor { command }) => run_doctor(&command, out),
        // `init` reads no config — it is the verb that exists because there is
        // none — so the §8 chain is deliberately not threaded through it.
        Some(Command::Init { dry_run }) => run_init(dry_run, mode, out, err),
        // `baseline` reads config — it evaluates the same rules `check` does, and
        // its minting predicate consults `must_land_on` — so the §8 chain is
        // threaded through it like any other rule-running verb.
        Some(Command::Baseline { prune, dry_run }) => {
            run_baseline(prune, dry_run, mode, &overrides, out, err)
        }
        Some(Command::Generate { command }) => run_generate(&command, out),
        // `exec` reads no config and renders no verdict: it runs what the caller
        // named and reports what that returned. The §8 chain is deliberately not
        // threaded through it — there is nothing here for policy to decide.
        // `exec` resolves config for exactly one reason — the output predicates
        // (CLOUD-117) — and renders no verdict of its own beyond them. An
        // unreadable authority is still a usage error here: a pattern table nobody
        // could read is a gate that silently did not run.
        Some(Command::Exec(request)) => run_exec(&request, &overrides, err),
        Some(Command::Capture { command }) => run_capture(&command, mode, out, err),
        // The one verb whose reach leaves this machine (CLOUD-1260). Declared
        // unclassified in `SURFACE` for that reason, so it is excluded from §5's
        // derived read-only allowlist by construction rather than by good
        // behaviour.
        Some(Command::Mcp { command }) => run_mcp(&command, &overrides, out, err),
        Some(Command::Target { command }) => run_target(&command, &overrides, mode, err),
        Some(Command::Hook { harness, instant }) => run_hook(
            harness,
            supplied_instant(instant.as_deref())?,
            mode,
            &overrides,
            out,
            err,
        ),
        // CLOUD-479. Touches NO config — this is the per-turn hot path, and the
        // whole point is that it costs less than the `jq` process it replaces.
        // `run_hook` loads policy only past its cheap refusals for the same
        // reason; this has no policy to load at all.
        Some(Command::HookField { harness, field }) => run_hook_field(harness, field, out),
        // The receipt verbs read their own git facts; the §8 config chain does
        // not apply — a receipt records policy (as a digest), it never resolves it.
        Some(Command::Receipt { command }) => run_receipt(command, mode, out, err),
        Some(Command::Policy { command }) => run_policy(command, &overrides, out),
        // `lint <kind>` reads text the caller names and answers about its shape.
        // The §8 config chain is deliberately not threaded through it: the schema
        // is engine structure, not repo policy, so there is no key for a config to
        // layer and nothing a `batten.local.toml` could weaken.
        Some(Command::Lint { command }) => match command {
            LintCommand::Brief { path, json } => run_lint_brief(path.as_deref(), json, out),
        },
        // Commit metadata is neither tree content nor a mediated call, so the §8
        // config chain supplies the patterns and git supplies the object. The
        // range is the caller's: `verify` and CI already agree on which commits a
        // branch produced, and deriving it again here would be a second authority
        // for that fact.
        Some(Command::Attribution { command }) => run_attribution(command, &overrides, out, err),
        // Same object as `attribution`, different question: the subject's shape
        // rather than the metadata's provenance (CLOUD-701).
        Some(Command::Commit { command }) => match command {
            CommitCommand::Check {
                json,
                range,
                message,
            } => run_commit_check(json, range.as_deref(), message.as_deref(), &overrides, out),
        },
        Some(Command::Worktree { command }) => match command {
            WorktreeCommand::Status { json } => run_worktree_status(json, &overrides, out),
        },
        Some(Command::Override { command }) => run_override(command, &overrides, out, err),
        Some(Command::Semver { command }) => run_semver(command, mode, out, err),
        Some(Command::Perf { command }) => run_perf(command, &overrides, out, err),
        Some(Command::Mutate { command }) => run_mutate(command, out, err),
        // The landing lease (CLOUD-1274). Every arm reaches the network, which
        // is why nothing on the `check` or `hook` surface may reach this module —
        // `policy/module-layering.rego` forbids both edges over the resolved use
        // graph rather than by review.
        Some(Command::Lease { command }) => run_lease(command, out, err),
        // The landing lap (CLOUD-1335). It reaches the network through `lease`
        // and the worktree through `gitwrite`, so the same two edges are
        // forbidden — transitively, which the layering table states rather than
        // leaves to follow.
        Some(Command::Land { command }) => run_land(&command, out, err),
        Some(Command::Wiring { command }) => run_wiring(&command, mode, err),
        // The refinement gate and the pull-time claim (CLOUD-1121). Both read
        // the payload the caller supplies — or, under `--issue`, the one the
        // engine already captured, which is the whole point of the row.
        Some(Command::Ready { command }) => run_ready(command, mode, &overrides, out, err),
        // The board sweep (CLOUD-186, CLOUD-1127). Judges a payload rather than
        // a tree, so it takes no config chain and no root: the evidence is what
        // the caller supplies, and the verdict is the predicate's alone.
        Some(Command::Landed { command }) => run_landed(command, mode, out, err),
        Some(Command::Claim { command }) => run_claim(command, mode, &overrides, out, err),
        // The green verdict (CLOUD-1143). Reads a reading, never the network:
        // the fetch stays with the poller that already holds the body.
        Some(Command::Checks { command }) => run_checks(command, out, err),
        Some(Command::Pr { command }) => run_pr(command, &overrides, mode, out, err),
        // The task registry (CLOUD-425). No config chain: the store is the git
        // dir's, and no key could layer over "what is running right now".
        Some(Command::Task { command }) => run_task(command, out, err),
        // One task per clone (CLOUD-428), on the same store and for the same
        // reason: the lock is the git dir's, and no config key could layer over
        // "is a second one of these already running here".
        Some(Command::Singleton { command }) => run_singleton(command, out, err),
        // The ledger is a committed file the consumer declares; the §8 config
        // chain supplies its path and taxonomy and nothing else layers.
        Some(Command::Defects { command }) => match command {
            DefectsCommand::Query {
                json,
                class,
                id,
                ungated,
            } => run_defects_query(
                json,
                class.as_deref(),
                id.as_deref(),
                ungated,
                &overrides,
                out,
            ),
            DefectsCommand::Add { dry_run } => run_defects_add(dry_run, mode, &overrides, err),
        },
        // The corpus is stdin's and nothing else (CLOUD-324); the §8 chain
        // supplies one ceiling and no second source of records.
        Some(Command::Design { command }) => match command {
            DesignCommand::Audit { json } => run_design_audit(json, &overrides, out),
        },
        Some(Command::Startup { repair, json }) => run_startup(repair, json, &overrides, out),
        Some(Command::Provision { command }) => match command {
            ProvisionCommand::Status { json } => run_provision_status(json, &overrides, out),
            ProvisionCommand::Apply { dry_run } => run_provision_apply(dry_run, &overrides, err),
        },
        // The store resolves itself from git facts and the OS state dir; the §8
        // config chain does not apply, because which store a checkout owns is
        // not a policy question and no `batten.toml` may answer it.
        Some(Command::State { command }) => match command {
            StateCommand::Adopt { store } => store::run_adopt(store.as_deref(), err),
            StateCommand::Record => run_state_record(&overrides, mode, err),
            StateCommand::Migrate => run_state_migrate(err),
            StateCommand::Settle {
                identity,
                disposition,
            } => run_state_settle(&identity, &disposition, err),
            StateCommand::List { json } => run_state_list(json, mode, out, err),
        },
        // The §8 config chain DOES apply, and only to the tool half: `record tool`
        // reads the `[[rule.tools]]` row that names the tool, its pin and the
        // input, which is exactly the committed authority a `--config-from` is
        // meant to pin. That is also what stops a caller keying a record to
        // anything the config does not already declare (CLOUD-1265).
        Some(Command::Record { command }) => record::run(command, &overrides),
    }
}

/// Audit a design-evidence claim stream read on stdin (CLOUD-53).
///
/// The whole input is stdin: no config path, no filesystem walk, no second
/// source and therefore no precedence question (CLOUD-324). Config supplies
/// exactly one value — the per-capture ceiling — so this verb resolves the §8
/// chain for a number and reads its records from nowhere else.
///
/// The two channels answer differently on a clean corpus, and both are the
/// contract: plain prints **nothing** (§6, and the acceptance's own wording),
/// while `-J` emits its document unconditionally, because JSON that is sometimes
/// absent is unparseable.
fn run_design_audit(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    // `[design]` is authority-only, so there is no local layer to clamp against
    // today; the tighten-only call is the semantics, stated where it applies.
    let cap = design::effective_cap(
        config.design.and_then(|design| design.max_capture_bytes),
        None,
    );

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    // A malformed corpus is exit 1, never 2: the policy verdict is reserved for
    // a claim about the evidence, and "this is not the format" is a claim about
    // the invocation.
    let claims = design::parse(&raw)?;
    let problems = design::audit(&claims, cap);

    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&design::Report::new(&problems))?
        )?;
    } else {
        output::lines(out, &problems)?;
    }

    let findings: Vec<rules::Finding> = problems.iter().map(design::Problem::finding).collect();
    Ok(ExitCode::verdict(design::blocks(
        &findings,
        config.strictness,
        config.fail_on_warning,
    )))
}

/// Report which provisioned tools do not match the manifest (CLOUD-90).
///
/// A manifest with **no entries is not an error**, unlike `policy budget`'s
/// absent budget: zero entries is a complete and honest answer — this repository
/// provisions nothing — where a budget verb with no budget would be claiming to
/// have measured something it did not. The two absences are different claims.
/// Decide every `[[startup]]` row, repairing when asked (CLOUD-1324).
///
/// # Why one verb and a flag rather than two sub-verbs
///
/// `provision status`/`provision apply` split because they have different
/// subjects: one reads a checksum, the other fetches an artifact. Here both
/// halves decide the SAME rows against the SAME checks, and the fix half's
/// report is precisely the check re-run. Two sub-verbs would have to duplicate
/// the whole report, and a reader comparing them would be comparing two
/// renderings of one answer.
///
/// # Exit
///
/// `0` when every row is provisioned — on the first look or after this run's
/// repair — and `1` otherwise. Never `2`: a container that does not match what
/// the repository declares is the config-or-usage class, and a mediating harness
/// reading `2` as a policy denial must not be told this is one (§7). That is
/// `doctor`'s reasoning and this verb inherits it.
///
/// # The report
///
/// Pointer-only: each row's declared id and a verdict token, in declaration
/// order, so the output is byte-stable for a given tree (§6). Silence means
/// there were no rows to decide — which is not the same as every row passing,
/// and is why the count is always the last line.
fn run_startup(
    repair: bool,
    json: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let here = Path::new(".");
    let outcomes = if repair {
        startup::repair(here, &config.startup)
    } else {
        startup::evaluate(here, &config.startup)
    };
    let failed = outcomes.iter().filter(|outcome| !outcome.ok).count();

    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&outcomes)?)?;
    } else {
        // EVERY ROW, not only the failing ones, and deliberately unlike
        // `provision status`. A reader running this is asking whether the
        // container is right, and a silent pass over a row whose check never ran
        // is indistinguishable from a row that was never declared — which is the
        // could-not-look-as-clean failure the whole table exists to refuse.
        output::lines(out, &outcomes)?;
        writeln!(out, "startup: {} row(s), {failed} failed", outcomes.len())?;
    }
    // `Usage`, never `Violation` — `doctor`'s reasoning, inherited: a mediating
    // harness reads `2` as a policy denial, and "this container is not what the
    // repository declares" is not one (§7).
    Ok(if failed == 0 {
        ExitCode::Success
    } else {
        ExitCode::Usage
    })
}

fn run_provision_status(
    json: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let repo = git::repo_root(Path::new("."))?;
    let report = provision::status(&config.provisions, &provision::cache_root(&repo)?)?;

    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // Only the stale entries: a fresh one is not news, and an all-fresh run
        // prints nothing at all.
        for line in report.stale_lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::verdict(report.any_stale()))
}

/// Fetch, verify, and install every stale manifest entry (CLOUD-90).
///
/// Reports through `err`, never `out`: this verb writes to the cache and has no
/// document to emit, so its progress belongs on the messaging channel. That also
/// keeps the one thing it could print — what it installed — off a stream a
/// caller might be parsing.
fn run_provision_apply(
    dry_run: bool,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let repo = git::repo_root(Path::new("."))?;
    let cache = provision::cache_root(&repo)?;

    for entry in &config.provisions {
        // A checksum mismatch propagates as a `Denial` (exit 2) from here, so
        // the loop stops at the first bad artifact rather than going on to
        // install the rest under a verdict that already failed.
        let applied = provision::apply(entry, &cache, dry_run)?;
        let verb = match applied {
            provision::Applied::Installed => "installed",
            provision::Applied::AlreadyFresh => continue,
            provision::Applied::Previewed => "would install",
        };
        // Pointer-only: the entry and its pinned version, never a URL response
        // and never a byte of the artifact.
        writeln!(err, "provision: {verb} {} {}", entry.name, entry.version)?;
    }
    Ok(ExitCode::Success)
}

/// Scaffold the committed authority (CLOUD-206).
///
/// The channel split is §6's: **stdout carries the pointer** — the one path this
/// invocation is about — and stderr carries the messaging. The refusal is the
/// exception, and deliberately so: §7 defines exit `2` as a verdict whose reason
/// travels on stderr, so an already-present config prints nothing on stdout and
/// the reason unprefixed on stderr. A caller reading only stdout therefore sees a
/// path exactly when a path is what it got.
///
/// The `-n` preview is **not** ladder-gated, following `defects add`: a silenced
/// preview is a `--dry-run` that did nothing. The success line is, because a
/// caller that asked for `-q` after a write it requested wants the pointer and
/// not the prose.
fn run_init(
    dry_run: bool,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match init::apply(Path::new("."), dry_run)? {
        init::Outcome::Created => {
            writeln!(out, "{}", config::CONFIG_FILE)?;
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("wrote {}; run `batten check` next", config::CONFIG_FILE),
            )?;
            Ok(ExitCode::Success)
        }
        init::Outcome::WouldCreate => {
            writeln!(out, "{}", config::CONFIG_FILE)?;
            writeln!(err, "init: would write {}", config::CONFIG_FILE)?;
            Ok(ExitCode::Success)
        }
        // Unprefixed and ungated: this is the verdict, not a message about one.
        // Built through `Refusal` rather than a `format!` of its own — this is a
        // deny site, and CLOUD-122's contract is that every deny points to a fix
        // structurally rather than because its author remembered to name one.
        init::Outcome::Exists => {
            let refusal = Refusal::declared(
                init::CONFIG_EXISTS,
                verdict::Native::InitWouldOverwrite,
                &[verdict::Subject::Path {
                    path: config::CONFIG_FILE.to_owned(),
                }],
                Fix::Run(format!(
                    "edit {file} in place, or move it aside and run `batten init` again",
                    file = config::CONFIG_FILE
                )),
            );
            output::verdict(err, &refusal.render())?;
            Ok(ExitCode::Violation)
        }
    }
}

/// Record the findings that already exist, so only new ones fail (CLOUD-67).
///
/// Two modes over one artifact. Without `--prune` this **mints**: it runs the
/// same rules `check` runs and records their identities, behind
/// [`baseline::mintable`] — only landed, committed state may be baselined, which
/// is the whole thing that keeps a bulk suppression inside the threat model.
/// With `--prune` it **subtracts**: entries nothing backs are dropped and reduced
/// anchors ratchet down, which needs no mint gate because it can only ever
/// suppress less.
///
/// `rules::run_static` deliberately, not `run_all`: the predicate this baseline
/// serves is `batten check`'s, so it must cover exactly that surface — and it
/// keeps a `write` verb from reaching user-supplied code on the way.
///
/// Output is pointer-only (rule 4): a count and `rule <digest>` pointers, never a
/// baselined line.
///
/// # Errors
///
/// Propagates config resolution, the rule scan, and the store write. Raises a
/// [`UsageError`] (exit `1`) when no findings store is bound to this checkout.
fn run_baseline(
    prune: bool,
    dry_run: bool,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = anchor();
    let config = resolve::resolve(&root, overrides)?;
    let scan = rules::run_static(
        &config.rules,
        &config.provisions,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        &root,
    )?;

    if prune {
        let Some(existing) = baseline::load(&root)? else {
            output::verdict(
                err,
                "baseline --prune: no baseline is recorded for this checkout",
            )?;
            return Ok(ExitCode::Violation);
        };
        let (pruned, drifted) = baseline::prune(&existing, &scan);
        let dropped = existing.entries.len() - pruned.entries.len();
        for item in &drifted {
            writeln!(out, "{}", item.entry.pointer())?;
        }
        if dry_run {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("baseline: would drop {dropped} entr{}", plural(dropped)),
            )?;
            return Ok(ExitCode::Success);
        }
        let file = baseline::save(&root, &pruned)?;
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "baseline: dropped {dropped} entr{}, {} remain ({})",
                plural(dropped),
                pruned.entries.len(),
                file.display()
            ),
        )?;
        return Ok(ExitCode::Success);
    }

    // The minting gate. A refusal is the verdict, not an error: exit 2, on the
    // one table, unprefixed — a host reads that as a policy answer rather than
    // as Batten falling over (§7).
    if let Some(refusal) = baseline::mintable(&root, config.must_land_on.as_deref())? {
        for line in refusal.lines() {
            output::verdict(err, &line)?;
        }
        return Ok(ExitCode::Violation);
    }

    let target = worktree::land_target(&root, config.must_land_on.as_deref())?;
    let sha = match target.as_deref() {
        Some(reference) => git::resolve_ref(&root, reference)?,
        None => None,
    };
    let commit = git::head_commit(&root)?;
    let minted = baseline::mint(&scan, target, sha, commit, waiver::today()?);

    for entry in &minted.entries {
        writeln!(out, "{}", entry.pointer())?;
    }
    let count = minted.entries.len();
    if dry_run {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("baseline: would record {count} identit{}", plural(count)),
        )?;
        return Ok(ExitCode::Success);
    }
    let file = baseline::save(&root, &minted)?;
    // The audit line every mint owes, unconditional at `Normal` for the same
    // reason a waiver's is: a suppression this size must not be a detail a
    // default run has to ask for. Pointer-only — a ref, a sha and a count.
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!(
            "baseline: recorded {count} identit{} against {} {} ({})",
            plural(count),
            minted.minted.reference.as_deref().unwrap_or("-"),
            minted
                .minted
                .sha
                .as_deref()
                .map_or("-", |sha| &sha[..12.min(sha.len())]),
            file.display()
        ),
    )?;
    Ok(ExitCode::Success)
}

/// The `y`/`ies` suffix for `entr…` and `identit…`, which share one.
const fn plural(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

/// Report work that is uncommitted, unpushed, or not landed (CLOUD-51).
///
/// An absent `must_land_on` **falls back to the remote's recorded default
/// branch**, and where no target resolves at all the verb still reports every
/// other fact, with the unlanded component rendered `not-computable`.
///
/// This was a usage error until CLOUD-51's `DoD` audit: refusing the whole
/// invocation looked like the safe reading and is the opposite of one. A repo
/// with no `must_land_on` got *nothing* — not the dirty tree, not the branch
/// tracking nothing — so the one configuration most likely to be a fresh,
/// at-risk checkout was also the one the gate stayed silent about. Not-computable
/// must never read as clean, and it must never suppress the facts beside it. A
/// configured target that resolves to no commit is still exit 1, raised by
/// `git::landing`: a target the author named and got wrong is a config error,
/// which is a different thing from naming none.
fn run_worktree_status(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let target = config.must_land_on.as_deref();
    // The repo root, not the process directory: the three categories are
    // properties of the repository, and answering from a subdirectory would
    // report a clean tree for a dirty one one level up.
    let repo = git::repo_root(Path::new("."))?;
    let at_risk = worktree::status(&repo, target)?;

    if json {
        // Unconditional, including the clean run: JSON that is sometimes absent
        // is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&at_risk)?)?;
    } else {
        // Clean prints nothing — `lines()` is empty exactly then, so silence is
        // structural here rather than a branch that could disagree with `any()`.
        for line in at_risk.lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::verdict(at_risk.any()))
}

/// The declared ledger, or a usage error naming what is missing (CLOUD-52).
///
/// A verb over a ledger nobody declared measured nothing, and answering "no
/// records" there would be the false green the engine exists to catch — the same
/// reading `policy budget` gives an absent budget.
fn declared_ledger(overrides: &Overrides) -> Result<(defects::Defects, PathBuf)> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let declared = config.defects.ok_or_else(|| {
        UsageError::raise(format!(
            "no [defects] in {}; there is no ledger to read",
            config::CONFIG_FILE
        ))
    })?;
    let repo = git::repo_root(Path::new("."))?;
    let path = repo.join(&declared.path);
    Ok((declared, path))
}

/// Read and parse the declared ledger. An absent file is an empty ledger — the
/// ordinary state before the first record.
fn read_ledger(path: &Path) -> Result<Vec<defects::Record>> {
    defects::parse(&std::fs::read_to_string(path).unwrap_or_default())
}

/// List recorded defects, as pointers (CLOUD-52).
fn run_defects_query(
    json: bool,
    class: Option<&str>,
    id: Option<&str>,
    ungated: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let (declared, path) = declared_ledger(overrides)?;
    let records = read_ledger(&path)?;

    // One filter, not a conjunction: the flags are alternative ways to name a
    // subset, and combining them would need a precedence nobody asked for.
    // Refusing the combination is clearer than picking a winner silently.
    let named = [class.is_some(), id.is_some(), ungated]
        .iter()
        .filter(|set| **set)
        .count();
    if named > 1 {
        return Err(UsageError::raise(
            "defects query: --class, --id and --ungated are alternative filters; name one",
        ));
    }
    let filter = match (class, id, ungated) {
        (Some(class), _, _) => defects::Filter::Class(class),
        (_, Some(id), _) => defects::Filter::Id(id),
        (_, _, true) => defects::Filter::Ungated,
        _ => defects::Filter::All,
    };

    if json {
        // Sorted by id, and emitted unconditionally including the empty answer:
        // JSON that is sometimes absent is unparseable.
        let mut matched: Vec<&defects::Record> = records
            .iter()
            .filter(|record| filter.admits(record))
            .collect();
        matched.sort_by(|a, b| a.id.cmp(&b.id));
        writeln!(out, "{}", serde_json::to_string_pretty(&matched)?)?;
    } else {
        // Pointers, then the count the DoD asks for on its own trailing line.
        // Unconditional, including `0`: the count is the answer to "how many",
        // and an empty listing that says nothing cannot be told from a filter
        // the caller misspelled.
        let lines = defects::query_lines(&records, &declared.path, filter);
        for line in &lines {
            writeln!(out, "{line}")?;
        }
        writeln!(out, "{} record(s)", lines.len())?;
    }
    Ok(ExitCode::Success)
}

/// Append records read as JSONL on stdin (CLOUD-52).
///
/// Idempotent on a byte-identical row, which is what makes a half-finished
/// import safe to re-run; the same id with different content is refused, because
/// that is a revision and revisions append with `supersedes`.
fn run_defects_add(
    dry_run: bool,
    mode: Mode,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (declared, path) = declared_ledger(overrides)?;

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let incoming = defects::parse(&raw)?;
    if incoming.is_empty() {
        return Err(UsageError::raise(
            "defects add: stdin carried no record; an add that adds nothing is a mistake, not a no-op",
        ));
    }
    // The taxonomy is config's, so an unknown class is refused here rather than
    // written and caught later by the gate — a ledger is append-only, so a bad
    // row admitted once cannot be taken back.
    let problems = defects::validate_records(&incoming, &declared.classes);
    if let Some(problem) = problems.first() {
        return Err(UsageError::raise(format!(
            "defects add: stdin line {} is {}; `classes` in {} declares the taxonomy",
            problem.line,
            problem.id,
            config::CONFIG_FILE
        )));
    }

    let existing = read_ledger(&path)?;
    let (summary, fresh) = defects::plan(&existing, &incoming)?;

    if dry_run {
        // The one line this verb prints unconditionally: `-n` exists to be read,
        // and the would-append count IS the migration acceptance (§5). It is a
        // *preview*, not a report of what happened, so the ladder does not gate
        // it — a silenced preview is a `-n` that did nothing.
        writeln!(
            err,
            "defects add: would append {} record(s), {} already present",
            summary.appended, summary.already
        )?;
        return Ok(ExitCode::Success);
    }
    if !fresh.is_empty() {
        let mut body = String::new();
        for record in &fresh {
            body.push_str(&record.line()?);
            body.push('\n');
        }
        // Append, never rewrite: the file is opened in append mode, so this verb
        // is structurally incapable of the edit the gate refuses.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;
        file.write_all(body.as_bytes())?;
    }
    // Silence on the ordinary path (§5: `add` prints nothing on success). The
    // counts ride the ladder at `Verbose`, where a caller who asked for them
    // gets them and a script that did not is not made to parse them.
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!(
            "defects add: appended {}, already present {}",
            summary.appended, summary.already
        ),
    )?;
    Ok(ExitCode::Success)
}

/// Bind the store, scan this ref, and fold the findings in as its instances.
///
/// **The scan is `rules::run_static`** — the read-effect surface, no process
/// spawn. A recording verb that could execute a configured command would put
/// user-supplied code behind a store write, which is a different and much larger
/// promise than "remember what the read-only gates found".
///
/// A detached `HEAD` records **nothing**, loudly. An observation is keyed by ref,
/// and a detached head has none; inventing a synthetic one would mint an
/// instance that ref-death GC could never collect, because the ref it names
/// never existed to die.
///
/// When a session is declared ([`session::SESSION_ENV`]) this also records the
/// lineage edge and advances **its own** fold position
/// ([`session::HOLDER_RECORD`]) — never a drain's, since this verb folds shards
/// whether or not anything reached an agent (CLOUD-83).
fn run_state_record(overrides: &Overrides, mode: Mode, err: &mut dyn Write) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    // **The ref comes from HERE, not from `repo`.** `repo_root` answers with the
    // MAIN worktree's root — which is exactly what makes every linked worktree
    // share one store — so asking it for the branch would report the main
    // checkout's ref no matter which worktree the scan ran in, and every
    // worktree's observations would pile onto one context. Measured: the
    // worktree-pair fixture recorded both scans as `refs/heads/main`.
    let Some(branch) = git::current_branch(Path::new("."))? else {
        return Err(UsageError::raise(
            "HEAD is detached, so this scan belongs to no ref; check out a branch to record it",
        ));
    };
    let context = findings::Context::new(format!("refs/heads/{branch}"));
    let commit = git::head_commit(Path::new("."))?;

    let config = resolve::resolve(Path::new("."), overrides)?;
    // `run_recorded`, not `run_static`: a spawning kind is WITHHELD here rather
    // than refused. The refusal is right for `check`, whose silence reaches a
    // human as an exit code and nothing else, and wrong for this verb — it
    // returns before any work, so one `command` or `secrets` rule in the config
    // cost the repository its whole store write, the transcript detectors
    // included (CLOUD-97 never once evaluated in this repository for exactly
    // that reason). Withholding is honest here because `record` below folds
    // `not_evaluated` into the store, where a withheld rule's findings HOLD.
    let scan = rules::run_recorded(
        &config.rules,
        &config.provisions,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        Path::new("."),
    )?;
    if !scan.not_evaluated.is_empty() {
        // Never silent: a rule that did not look must say so, or a clean-looking
        // record is the false green. The COUNT carries that on the default rung
        // and the ids ride `Verbose` — this fires at every turn end, and sixteen
        // rule ids on every one is how a line stops being read (`stop-guard`'s
        // own lesson about spending a channel). Ids are the config author's own
        // tokens rather than content, so the higher rung is a noise decision,
        // not a rule-4 one.
        let withheld: Vec<&str> = scan.not_evaluated.keys().map(String::as_str).collect();
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "state record: {} rule(s) not evaluated, their findings held",
                withheld.len()
            ),
        )?;
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            &format!("state record: not evaluated: {}", withheld.join(", ")),
        )?;
    }

    let bound = store::commit(store::resolve(&repo)?)?;
    if let Some(note) = &bound.note {
        writeln!(err, "batten: {note}")?;
    }

    // The store's own version decides what gets written, never this binary's
    // (CLOUD-78's write-old rule). A store newer than this binary is read-only:
    // it still dedupes, it just does not persist, and it says so rather than
    // reporting a record that did not happen.
    let access = journal::open(&bound.dir)?;
    if let journal::Access::DegradedReadOnly { reason, .. } = &access {
        writeln!(err, "batten: degraded read-only: {reason}")?;
        writeln!(err, "batten: state record {context}: persisted:false")?;
        return Ok(ExitCode::Success);
    }
    let schema = access.format().findings_schema;

    // The worktree actually scanned, not the main root — this is metadata for a
    // human reading a report, and naming the wrong directory would misdirect it.
    let here = std::env::current_dir().ok();
    let recorded = findings::record(
        &bound.dir,
        &context,
        &commit,
        here.as_deref().and_then(Path::to_str),
        &scan.findings,
        schema,
        // The rules that never looked. Without this the pass below reads their
        // silence as "clean" and resolves every finding they cover (CLOUD-81).
        &scan.not_evaluated,
    )?;

    // The transcript-substrate detectors (CLOUD-97, CLOUD-98), folded in beside
    // the rule scan rather than through it: their identities are sequences over
    // the session's event order, which `rules::run_static` has no input for and
    // no vocabulary to express. They run AFTER `record` on purpose — that pass
    // resolves what this context no longer sees, and a raise written before it
    // would be reasoning about a store mid-update.
    register_transcript_detectors(
        &repo,
        &Recording {
            context: &context,
            commit: &commit,
            store_dir: &bound.dir,
            schema,
        },
        &config,
        mode,
        err,
    )?;

    // Fold any dispositions this worktree journalled since the last record. A
    // lost lock race is not a failure — the entries stay in the shard and the
    // next record folds them — so it reports and carries on.
    let merged = journal::merge(&bound.dir)?;
    if merged == journal::Merge::Busy {
        writeln!(
            err,
            "batten: shard-merge busy; dispositions stay queued in this worktree's shard"
        )?;
    }

    // Ref-death GC rides the same verb: the live set is what exists now, so a
    // branch deleted since the last record loses its instances here.
    let live = git::refs(&repo)?
        .into_iter()
        .map(findings::Context::new)
        .collect();
    let dropped = findings::gc(&bound.dir, &live)?;
    if dropped > 0 {
        // GC's half of the cursor handshake: a new generation, so every
        // outstanding drain cursor resyncs instead of computing a delta against
        // records that are gone.
        journal::new_generation(&bound.dir)?;
    }

    // The session's durable resume point (CLOUD-83), recorded LAST so the stored
    // cursor names the generation this run finished in — a GC above may have
    // rotated it, and a cursor saved before that would name a dead one and force
    // a resync this process already knows the answer to.
    record_session_position(&bound.dir, mode, err)?;

    // Pointer-only counts on stderr; `record` emits no data document, so the
    // stdout channel stays empty for it.
    writeln!(
        err,
        "batten: state record {context}: {} minted, {} updated, {} resolved, {} held, \
         {dropped} instances GC'd",
        recorded.minted, recorded.updated, recorded.resolved, recorded.held
    )?;
    Ok(ExitCode::Success)
}

/// Record this session's lineage edge and fold position, when one is declared.
///
/// Split out because it is a different question from "what did this scan find",
/// and because the whole of it is skipped when no session is declared: a host
/// that supplies none is a repository not using this, and an absent session must
/// leave the store and this verb's output byte-identical to before
/// ([`transcript`]'s absent-is-not-empty law).
///
/// The note rides the `Verbose` rung rather than the default line. `state
/// record`'s one-line report is a byte-stable contract, and a resume position is
/// detail for a caller who asked — not a second sentence every consumer must now
/// parse.
///
/// **Not reachable on the degraded read-only path**: [`run_state_record`] returns
/// before the merge there, so a binary that may not write the store does not
/// write a session record either.
fn record_session_position(store_dir: &Path, mode: Mode, err: &mut dyn Write) -> Result<()> {
    let Some(declared) = session::declared() else {
        return Ok(());
    };
    let observed = session::observe(store_dir, &declared)?;
    let root = session::root(store_dir, &declared.key)?;
    let held = session::load_cursor(store_dir, &root, session::HOLDER_RECORD)?;
    // The same `since` every reader uses, so a rotated generation forces the
    // resync here exactly as it would anywhere else — this verb gets no private
    // reading of a cursor's validity.
    let drained = journal::since(store_dir, held.as_ref())?;
    let resumed = match &drained {
        journal::Drain::Delta { entries, .. } => format!("resumed, {} new", entries.len()),
        journal::Drain::FullResync { reason, .. } => format!("full resync ({reason})"),
    };
    session::save_cursor(store_dir, &root, session::HOLDER_RECORD, drained.cursor())?;

    // Pointer-only (rule 4): the lineage root as a fingerprint prefix and the
    // walk's depth, never the host's session id and never an entry.
    let lineage = if root.truncated {
        format!("lineage {} (truncated at {})", root.short(), root.depth)
    } else if root.depth > 0 {
        format!("lineage {} (+{})", root.short(), root.depth)
    } else {
        format!("lineage {}", root.short())
    };
    let conflict = if observed == session::Observed::ParentConflict {
        "; declared parent differs from the recorded one, which stands"
    } else {
        ""
    };
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!("state record: session {lineage}: {resumed}{conflict}"),
    )?;
    Ok(())
}

/// Upgrade the store's record version. The one explicit upgrade path.
///
/// A `write` verb by declaration and in fact: it rewrites every record. No read
/// path may do this, which is what keeps a routine `check` in one worktree from
/// rewriting a store an older binary is using in another.
fn run_state_migrate(err: &mut dyn Write) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        return Err(UsageError::raise(
            "no store is bound to this repository; run `batten state adopt` first",
        ));
    };
    let migrated = journal::migrate(&dir)?;
    if migrated.from == migrated.to {
        writeln!(
            err,
            "batten: state migrate: already at record version {}",
            migrated.to
        )?;
    } else {
        writeln!(
            err,
            "batten: state migrate: {} record(s) {} -> {}",
            migrated.records, migrated.from, migrated.to
        )?;
    }
    Ok(ExitCode::Success)
}

/// `batten state settle`: answer a stored finding (CLOUD-587).
///
/// # Why this verb has to exist
///
/// CLOUD-78 gave every finding a three-valued `disposition`, `journal::merge`
/// folds it, `FindingRecord::merge_disposition` joins two by precedence and
/// `stop.rs` READS it — `deny-stop` means at-risk work or an undischarged
/// denial, where undischarged is `disposition == None`. **Nothing minted one.**
/// The only producers anywhere in the tree were unit tests, so the field was
/// read by a gate, joined by a merge rule, persisted by a journal, and
/// unreachable from any caller.
///
/// That bit once CLOUD-98 landed `bypass.rs`, whose finding anchors to an
/// immutable transcript event: a bypass that happened, happened, so
/// re-evaluation keeps finding it and the observation never resolves to zero.
/// The finding is right to persist; what was missing is the answer channel.
///
/// # What it deliberately does not do
///
/// It writes through [`journal::append`], the append that already exists, so
/// there is no second writer and no new lock. It does not touch
/// [`crate::findings::Disposition::merge`], which stays the one join — this adds
/// a caller, never a second convergence rule. And it does not clear a
/// STATE-anchored finding by any other route: those clear by the condition
/// vanishing, and answering one would be a bypass of the work itself.
///
/// # Errors
///
/// [`UsageError`] (→ exit `1`) when no store is bound, when the identity is not
/// a fingerprint, or when the token is not a declared disposition. Recording a
/// disposition is bookkeeping, never a verdict, so the success path is exit `0`
/// and no finding it settles can move an exit code.
fn run_state_settle(identity: &str, disposition: &str, err: &mut dyn Write) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        return Err(UsageError::raise(
            "no store is bound to this repository; run `batten state adopt` first",
        ));
    };
    let Ok(fingerprint) = crate::identity::Fingerprint::from_hex(identity) else {
        return Err(UsageError::raise(format!(
            "`{identity}` is not a finding identity; `batten state list` prints the              fingerprint each finding is stored under"
        )));
    };
    // NAMED, never guessed. An unrecognised token is refused rather than folded
    // to a default: a disposition is an agent's answer, and an answer nobody
    // gave is the un-auditable settlement this verb exists to prevent.
    let Some(decided) = findings::Disposition::ALL
        .iter()
        .copied()
        .find(|candidate| candidate.as_str() == disposition)
    else {
        let known: Vec<&str> = findings::Disposition::ALL
            .iter()
            .map(|entry| entry.as_str())
            .collect();
        return Err(UsageError::raise(format!(
            "`{disposition}` is not a disposition; declared: {}",
            known.join(", ")
        )));
    };
    // THE RECORD MUST EXIST. `journal::merge` keeps an entry whose record it
    // cannot find, so appending for an unknown identity would silently succeed
    // and settle nothing a reader could ever see — the shape CLOUD-845 calls a
    // vacuous pass, one surface over.
    if findings::load_one(&dir, fingerprint)?.is_none() {
        return Err(UsageError::raise(format!(
            "no stored finding has identity {identity}; `batten state list` prints              what this store holds"
        )));
    }
    journal::append(
        &dir,
        &journal::shard_id(&repo),
        &journal::Entry {
            identity: fingerprint.to_hex(),
            rule: String::new(),
            origin: journal::Origin::Settle,
            context: None,
            // NEITHER FIELD IS THIS WRITER'S. `observation` is occurrence state
            // and belongs to `findings::record`; `presentation` is the drain's
            // suppression record and `merge` takes it from `Origin::Drain`
            // alone. A settle that wrote either would be a second authority on
            // a field it knows nothing about.
            observation: None,
            disposition: Some(decided),
            presentation: findings::Presentation::Shown,
        },
    )?;
    // POINTER-ONLY (rule 4): the identity and the token. These findings are
    // drawn from a transcript, so the content is exactly what must not travel.
    writeln!(err, "batten: state settle: {identity} {}", decided.as_str())?;
    Ok(ExitCode::Success)
}

/// Navigate a frozen capture (CLOUD-121).
///
/// A dispatcher only. The three sub-verbs are separate functions rather than
/// three arms of one match, because a single body carrying all of them crossed
/// the workspace's own function-length lint — and the lint was right: `show`
/// resolves a selection, `list` filters a directory, and `prune` removes, which
/// are three jobs sharing nothing but a repository root.
fn run_capture(
    command: &cli::CaptureCommand,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    match command {
        cli::CaptureCommand::Show {
            handle,
            lines,
            grep,
            raw,
            bytes,
            json,
        } => run_capture_show(
            &repo,
            handle,
            &ShowRequest {
                lines: lines.as_deref(),
                grep: grep.as_deref(),
                raw: *raw,
                byte_range: bytes.as_deref(),
                json: *json,
            },
            out,
            err,
        ),
        cli::CaptureCommand::Find {
            key,
            tools,
            key_at,
            raw,
            json,
        } => run_capture_find(
            &repo,
            FindRequest {
                key,
                tools,
                key_at: key_at.as_deref(),
                raw: *raw,
                json: *json,
            },
            out,
            err,
        ),
        cli::CaptureCommand::List {
            stream,
            calls,
            json,
        } => run_capture_list(&repo, stream.as_deref(), *calls, *json, out),
        cli::CaptureCommand::Prune { yes, dry_run } => {
            run_capture_prune(&repo, *yes, *dry_run, mode, err)
        }
    }
}

/// `batten mcp call` (CLOUD-1260).
///
/// **Three layers, and each is a different answer.** Dispatch resolves the wiring
/// a declared source names, makes the call the session was going to make anyway,
/// and stores the response whole. Reduction turns the stored response into what a
/// `[[mcp.result]]` row declares. What reaches the caller is a pointer, a delta
/// and that reduction; the payload reaches the store and stops there.
///
/// # Errors
///
/// An internal error (→ exit `3`) when no declared source resolves the server, or
/// when one resolves and will not read, or when the exchange cannot complete.
/// **All three are could-not-look and none is a policy verdict**, which is why
/// none of them is exit `2`: §7's table is total and has no per-verb exception,
/// and a `2` here would tell every harness with a pre-tool hook that policy
/// refused a call the network dropped. A malformed `params` is exit `1`, because
/// that is a statement about the invocation.
fn run_mcp(
    command: &cli::McpCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let cli::McpCommand::Call {
        server,
        method,
        params,
    } = command;
    let repo = git::repo_root(Path::new("."))?;
    let resolved = resolve::resolve(Path::new("."), overrides)?;
    let config = resolved.mcp.clone().unwrap_or_default();

    // The arguments are the CALLER's document and are parsed before anything is
    // dispatched: a malformed object is the caller's mistake, and discovering it
    // after the call would mean a round trip nobody can use.
    let params: serde_json::Value = match params {
        Some(raw) => serde_json::from_str(raw).map_err(|err| {
            UsageError::raise(format!(
                "mcp call: the params are not a readable JSON document: {err}"
            ))
        })?,
        None => serde_json::json!({}),
    };

    let wiring = match mcp::wiring(&config, &repo, server) {
        Ok(wiring) => wiring,
        // POINTER-ONLY, and loudly. The three answers stay apart in the message
        // because a repository that declared no source, a root this host does not
        // set and a wiring file halfway through an edit are different facts, and
        // collapsing them is how a gate reports green over a connector nobody
        // configured.
        //
        // THEY ALSO LAND IN TWO DIFFERENT EXIT CLASSES, and getting that wrong was
        // this verb's own defect. An UNDECLARED table is a statement about the
        // INVOCATION: the repository declares nowhere to dispatch, nothing was
        // attempted, and nothing failed — which is exit `1`, the same answer
        // `target prune` gives a repository that declares no floor. The other two
        // are could-not-look about the WORLD — the root is unset, the file is
        // absent, the bytes will not parse — which is exit `3`.
        //
        // Reading the first as `3` made the verb claim an internal failure over a
        // config that was simply silent; `pointer_only.rs`'s sweep is what caught
        // it, by refusing to draw any conclusion from a run that failed
        // internally. The split is more discriminating than the collapse, not
        // less: three causes across two classes.
        Err(mcp::Unresolved::Undeclared) => {
            return Err(UsageError::raise(format!(
                "mcp call: {server} cannot be dispatched — {}",
                mcp::Unresolved::Undeclared.pointer()
            )));
        }
        Err(unresolved) => {
            return Err(anyhow::anyhow!(
                "mcp call: {server} cannot be dispatched — {}",
                unresolved.pointer()
            ));
        }
    };

    let result = mcp::dispatch(&wiring, method, &params)?;
    file_and_report(
        &repo,
        &McpAnswer {
            config: &config,
            method,
            source: &wiring.source,
            result: &result,
            mints: &resolved.mints,
            patterns: &resolved.patterns,
        },
        out,
        err,
    )
}

/// What `mcp call` has in hand once the exchange has completed.
///
/// A struct rather than six positionals, for [`ShowRequest`]'s reason, and split
/// out at all because the verb has two halves that fail differently: everything
/// before the socket can refuse, and everything after it must not — the call has
/// already happened, so an error past this point loses the answer the caller paid
/// for.
struct McpAnswer<'a> {
    /// The table the reduction is declared in.
    config: &'a mcp::McpConfig,
    /// The method that was called.
    method: &'a str,
    /// Which `[[mcp.source]]` row resolved the wiring, by id.
    source: &'a str,
    /// The JSON-RPC result, still framed.
    result: &'a serde_json::Value,
    /// The receipts this repository mints from a tool result.
    ///
    /// Borrowed rather than resolved here: this boundary already loaded the
    /// config, and a second load would be a second answer to what the rows are.
    mints: &'a [crate::mint::Declared],
    /// The named-regex table, for a body's `{authority:…}` piece.
    patterns: &'a [crate::pattern::NamedPattern],
}

/// Store the response, record the call, and print a pointer plus the reduction.
///
/// # Errors
///
/// Only for a failure to write the answer out. The store and the call log are
/// **reported and never raised**: the exchange has already happened by the time
/// this runs, and refusing here would turn a completed dispatch into an error.
fn file_and_report(
    repo: &Path,
    answer: &McpAnswer<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let McpAnswer {
        config,
        method,
        source,
        result,
        mints,
        patterns,
    } = *answer;
    // THE UNFRAMED PAYLOAD IS WHAT THE STORE HOLDS, and that is a fidelity
    // requirement rather than a preference. `capture::find` resolves a stored
    // response by a key at a declared path — `id` by default — and that is how
    // `ready lint --issue`, `claim check --issue` and the board gates reach a
    // payload without its bytes entering anyone's context. Measured against this
    // repository's own store: the harness files the DECODED content, `id` at the
    // top level. Filing the JSON-RPC envelope here instead would put `id` two
    // levels down, every one of those lookups would silently resolve nothing, and
    // the gates would report could-not-look over a store that was full.
    let payload = mcp::payload(result);
    let whole = serde_json::to_vec(&payload.value)?;
    let stored = capture::store(repo, capture::Stream::Response, &whole)?;
    // The call log, so a later reader can resolve this response by the key it
    // carries without the bytes ever having entered anyone's context — the same
    // record `capture find` reads.
    capture::record_call(
        repo,
        &capture::CallRow {
            order: 0,
            session: session::declared().map(|it| it.key).unwrap_or_default(),
            source: "mcp-dispatch".to_owned(),
            host: "batten".to_owned(),
            tool: method.to_owned(),
            event: "dispatch".to_owned(),
            // THE HONEST WORD FOR WHAT WAS FILED. Bytes that went through a
            // decode are not a reproduction of the document the server framed —
            // a decode-then-reserialize round trip renormalizes key order and
            // escaping — so an unwrapped payload is `DecodedContent` and a
            // response whose framing was not recognised keeps `LexicalBytes`.
            // Both are complete, which is what `capture::find` requires.
            fidelity: if payload.unwrapped {
                capture::Fidelity::DecodedContent
            } else {
                capture::Fidelity::LexicalBytes
            }
            .as_str()
            .to_owned(),
            seen_at: None,
            class: None,
            digest: Some(stored.digest.clone()),
            absent: None,
        },
    )
    .unwrap_or_else(|failure| {
        // A STORAGE FAILURE IS REPORTED AND NEVER RAISED. The call has already
        // happened by the time this runs, so refusing here would turn a completed
        // dispatch into an error and lose the answer the caller paid for.
        let _ = writeln!(
            err,
            "batten: mcp call: the call log was not written: {failure}"
        );
    });

    // THE RECEIPT, FROM THE SAME ROWS THE HOOK PATH READS (CLOUD-1264). Closing
    // the raw read path is only safe if the reduced one mints what the raw one
    // minted: `an-update-owes-a-recent-read` and `claim`'s `refined-this-session`
    // both read an `issue-read` receipt, so a deny over the raw tool with nothing
    // minting here would refuse every board write in the repository.
    //
    // BEFORE THE REDUCTION, and that is the ordering decision. `mcp::reduce`
    // narrows the answer to a row's declared `fields`, so a receipt minted from
    // the reduction would resolve its `key_from` and `requires` through a
    // projection nobody declared for it — one `[[mcp.result]]` row would silently
    // decide whether an unrelated `[[mint]]` row fires. `payload.value` is the
    // unframed whole, which is exactly what the hook path passes.
    //
    // BEFORE THE EMITS, which use `?`. Minting after them would let a closed
    // stdout turn a completed dispatch into a run that wrote no receipt, and the
    // gate would then deny over a call that succeeded.
    //
    // AFTER THE CAPTURE AND THE CALL LOG, mirroring `record_post_tool`: the
    // record of the exchange is written first and the derived receipt second, so
    // a mint can never be the reason a capture is missing.
    mint_receipts(
        mints,
        method,
        &payload.value,
        repo,
        ready::Grammar::from_compiled(&crate::pattern::compiled(patterns))
            .ok()
            .as_ref(),
    );

    // THE TRANSPARENCY DEFAULT (CLOUD-418's mirror). A method no row declares is
    // returned WHOLE, and so is one whose row could not reach its payload: a
    // reducer that silently emitted a narrower answer over a node it never found
    // would be indistinguishable from a genuinely narrow row, which is the exact
    // failure this verb exists to prevent.
    //
    // THREE ANSWERS, NOT TWO, and collapsing the last two was this function's own
    // first defect: "no row declares this method" and "a row declared it and could
    // not reach its payload" both hand the response back whole, and reporting them
    // with one word would make a BROKEN row indistinguishable from an absent one —
    // the same conflation the module refuses at every other boundary. The second
    // is loud on stderr, because a reduction that quietly stopped applying is
    // exactly how the saving becomes notional.
    let declared = mcp::row_for(config, method);
    let reduced = declared.and_then(|row| mcp::reduce(row, &payload.value));
    let disposition = match (declared, &reduced) {
        (Some(_), Some(_)) => "reduced",
        (Some(_), None) => "unreduced",
        (None, _) => "undeclared",
    };
    if disposition == "unreduced" {
        writeln!(
            err,
            "batten: mcp call: {method} declares a reduction and its node was not reachable in \
             this response — passing the response through whole. Check the row's `node` and \
             `embedded` against what the server actually returned; the stored capture is the \
             evidence."
        )?;
    }
    let answer = match &reduced {
        Some(kept) => serde_json::Value::Object(kept.clone()),
        // The PAYLOAD rather than the envelope, so what a caller gets when no
        // reduction applies is the same document the store holds and the same one
        // the connector would have handed back — which is what "byte-identical to
        // no-Batten" has to mean here.
        None => payload.value.clone(),
    };
    let rendered = serde_json::to_string_pretty(&answer)?;

    // THE DELTA IS THE POINT AND IS REPORTED AS ONE. A pointer with no number
    // beside it makes the saving an impression; the two byte counts make it a
    // measurement anybody can check against the store.
    let emitted = u64::try_from(rendered.len()).unwrap_or(u64::MAX);
    let held = u64::try_from(whole.len()).unwrap_or(u64::MAX);
    // THE RECORD GOES TO STDERR AND THE PRODUCT TO STDOUT, which is `exec`'s split
    // and its reason: the answer belongs to whoever asked for it, and a record
    // ABOUT the call interleaved into that answer makes it unparseable. It is
    // pointer-only — a handle, a source id, a disposition and two byte counts,
    // never a byte of what was stored.
    writeln!(
        err,
        "batten: mcp call: {} {method} via {source} {disposition} — stored {held} bytes, emitted \
         {emitted}",
        stored.handle(),
    )?;
    writeln!(out, "{rendered}")?;
    Ok(ExitCode::Success)
}

/// `batten target prune` (CLOUD-1030).
fn run_target(
    command: &cli::TargetCommand,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // THE CWD, NEVER THE REPOSITORY ROOT, and both halves of this verb depend on
    // it. §8 forbids a directory walk, so the authority is `./batten.toml` — and
    // resolving the repo root first would silently read the enclosing
    // repository's table from inside a nested tree, which is how every case in
    // this suite answered with the real floor instead of its own (measured: the
    // fixture declared 6000 and the run reported 6242). The build tree is
    // cwd-relative for the same reason the predecessor's `$root` was: the
    // "is there a manifest beside it" discriminator is a question about the
    // caller's directory, and it decides nothing if the path was rewritten first.
    let here = Path::new(".");
    let resolved = resolve::resolve(here, overrides)?;
    let cli::TargetCommand::Prune { yes, dry_run, root } = command;
    let Some(declared) = resolved.prune.as_ref() else {
        // A repository that declares no `[prune]` has no floor to judge against,
        // and inventing one would be the core holding a number about somebody
        // else's build. Not a refusal: nothing was asked for.
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            "target prune: no [prune] table, so this repository declares no build tree to reclaim or floor to judge",
        )?;
        return Ok(ExitCode::Success);
    };
    let named = root.is_some();
    let tree = here.join(root.as_deref().unwrap_or(declared.root.as_str()));

    if *dry_run {
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            &format!(
                "target prune: would keep {} copy/copies per stem under {}, against a {}MB warm floor and a {}MB cold one",
                declared.keep,
                tree.display(),
                declared.warm.mb,
                declared.cold.mb
            ),
        )?;
        return Ok(ExitCode::Success);
    }
    if !*yes {
        // §4's refusal, `capture prune`'s reason unchanged: this removes build
        // artifacts, the primary caller is `verify`, and a gate that blocks on a
        // Y/N is a dead gate. Naming the flag is the whole remedy.
        return Err(UsageError::raise(
            "target prune: removing build artifacts is destructive and this never prompts — pass -y, \
             or -n to see what would go",
        ));
    }

    // THE LAP HISTORY IS OPTIONAL, and both halves of that are deliberate
    // (CLOUD-861). `$GIT_DIR` is where it lives, beside `batten-receipts/`; a
    // checkout without one — a fixture, an exported tree — has nowhere to keep a
    // history and decides on the declared floors alone, exactly as every run did
    // before the ratchet existed. A HEAD that cannot be read is not a reason to
    // refuse either: the sha is a pointer the report prints, never a key anything
    // is looked up by.
    //
    // THE CWD'S OWN `.git`, NEVER AN ANCESTOR'S, and this is the same defect #734
    // records for the config root one paragraph up — caught here by the suite
    // rather than by reading. `git::git_dir` walks up, so a fixture at
    // `target/tmp/<name>` resolved the ENCLOSING repository's git dir and every
    // case in the suite shared one lap journal: a run with a fabricated 99999MB
    // reading wrote a ratchet that the next case then judged itself against. The
    // authority is `./.git`, for the reason `./batten.toml` is the config's.
    let store = here
        .join(".git")
        .exists()
        .then(|| git::git_dir(here).ok())
        .flatten()
        .map(|git_dir| prune::LapStore {
            head: git::head_commit(here).map_or_else(
                |_| String::from("unknown"),
                |sha| sha.chars().take(8).collect(),
            ),
            git_dir,
        });
    let outcome = prune::prune(&tree, declared, named, store.as_ref())?;
    output::message(mode, output::Verbosity::Normal, err, &outcome.report())?;
    if outcome.clears_the_floor() {
        // THE BASIS, AFTER THE FLOOR AND ONLY ON THIS SURFACE (CLOUD-1158). The
        // floor refusal is the urgent one and comes first; this one asks the
        // slower question — is the number still measured against the tree it was
        // measured against — and it asks it here rather than at config load
        // because `Prune::validate` runs on every mediated tool call. See
        // `prune::Measured`.
        //
        // COULD-NOT-LOOK ALLOWS: `git.rs` states the posture every caller of
        // `tracked_paths` takes — a tree that cannot be enumerated is never
        // refused on the strength of a count nobody took.
        //
        // AND THE CWD'S OWN `.git` IS THE AUTHORITY, never an ancestor's, for the
        // reason the lap store above says: `open` walks up, so a fixture under
        // `target/tmp/` otherwise counts the ENCLOSING repository's index and is
        // refused for a basis that is not its own. Measured here as a fixture
        // declaring 1 file and being told the tree tracks 189.
        let index = here
            .join(".git")
            .exists()
            .then(|| git::tracked_paths(here).ok())
            .flatten();
        if let Some(tracked) = index {
            let paths: Vec<&str> = tracked.iter().map(String::as_str).collect();
            if let Some(drift) = prune::basis_drift(declared, &paths) {
                output::verdict(err, &drift.refusal())?;
                return Ok(ExitCode::Violation);
            }
        }
        return Ok(ExitCode::Success);
    }
    // THE VERDICT, and it is a violation rather than an internal failure: the
    // invocation was well-formed and the answer is "this tree cannot fit the
    // build the next lap will run". Exit 2 is that answer everywhere in this
    // engine, with no per-verb exception.
    output::verdict(err, &outcome.refusal(&tree))?;
    Ok(ExitCode::Violation)
}

/// What one `capture show` asked for: which window, and in which encoding.
///
/// Grouped rather than passed as five parameters, and the workspace's own
/// argument-count lint is what asked for it — correctly, because these are one
/// thing: a caller's request. Two selectors (`lines`, `grep`), one byte window
/// (`byte_range`), and two encodings (`raw`, `json`), whose legal combinations
/// [`run_capture_show`] decides in one place.
#[derive(Debug, Clone, Copy)]
struct ShowRequest<'a> {
    /// A 1-indexed inclusive line range.
    lines: Option<&'a str>,
    /// A literal substring.
    grep: Option<&'a str>,
    /// Write the selected bytes verbatim.
    raw: bool,
    /// A 0-indexed half-open byte range.
    byte_range: Option<&'a str>,
    /// Emit a byte-stable document.
    json: bool,
}

/// Read a frozen capture, with no second run of the command that made it.
///
/// **Always [`ExitCode::Success`]**, for the same reason [`run_state_list`] is:
/// this reports what a past run produced, and a verdict here would put a record
/// on the deny channel. A handle that names nothing is still a [`UsageError`] —
/// the caller asked about a capture that is not there, which is a statement about
/// the invocation, not a finding about the repository.
///
/// `--lines` and `--grep` together is refused rather than composed. Two selectors
/// have two readings — the intersection or the union — and picking one silently
/// would make the answer depend on a choice the caller never saw. A caller who
/// wants both greps first and then widens around what it found, which is the
/// navigation loop this verb exists to make possible.
fn run_capture_show(
    repo: &Path,
    handle: &str,
    asked: &ShowRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let ShowRequest {
        lines,
        grep,
        raw,
        byte_range,
        json,
    } = *asked;
    let parsed = capture::Handle::parse(handle)?;
    // REFUSED BEFORE ANYTHING IS READ, and refused rather than resolved
    // (CLOUD-918). `--raw` and `--json` are two encodings of one selection, and a
    // combination that had to pick between them silently is how a caller ends up
    // with base64 where it wanted bytes. `--lines` and `--grep` are line views,
    // which a byte stream is not — pairing either with `--raw` asks for two
    // different products at once.
    if raw && json {
        return Err(UsageError::raise(
            "capture show: --raw and --json are two encodings of the same selection; pass one. \
             --raw writes bytes, --json writes a byte-stable document",
        ));
    }
    if raw && (lines.is_some() || grep.is_some()) {
        return Err(UsageError::raise(
            "capture show: --raw writes bytes and --lines/--grep select decoded lines; pass \
             --bytes to narrow a raw read",
        ));
    }
    if byte_range.is_some() && (lines.is_some() || grep.is_some()) {
        return Err(UsageError::raise(
            "capture show: --bytes and --lines/--grep select differently; a byte range is not a \
             line range",
        ));
    }
    // A byte range is its own selection, so it is resolved ahead of the line
    // selectors rather than folded into their match — the two are not alternatives
    // over one axis.
    if raw || byte_range.is_some() {
        let (from, to) = match byte_range {
            Some(range) => parse_bytes(range)?,
            None => (None, None),
        };
        return run_capture_raw(
            repo,
            &parsed,
            RawRequest {
                from,
                to,
                raw,
                json,
            },
            out,
            err,
        );
    }
    let selection = match (lines, grep) {
        (Some(_), Some(_)) => {
            return Err(UsageError::raise(
                "capture show: --lines and --grep select differently; grep first, then widen \
                 around the line it names",
            ));
        }
        (Some(range), None) => capture::Selection::Lines {
            from: parse_line(range, 0)?,
            to: parse_line(range, 1)?,
        },
        (None, Some(needle)) => capture::Selection::Grep {
            needle: needle.to_owned(),
        },
        (None, None) => capture::Selection::Summary,
    };
    // The byte count is the store's to know, not the caller's: this record exists
    // only to name the file, and `select` reports the real length off the bytes.
    let record = capture::Capture {
        stream: parsed.stream.as_str(),
        bytes: 0,
        digest: parsed.digest.clone(),
    };
    let bytes = capture::read(repo, &record).map_err(|_| {
        UsageError::raise(format!(
            "capture show: no capture at {parsed} — `batten capture list` names the ones this \
             repository holds"
        ))
    })?;
    let answer = capture::select(&parsed, &bytes, &selection);
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&answer)?)?;
    } else if matches!(selection, capture::Selection::Summary) {
        // The pointer, in the `<pointer> <fact>` shape every other verb here
        // emits, so a caller needs no second parser.
        writeln!(
            out,
            "{} {} bytes {} lines",
            answer.handle, answer.bytes, answer.lines
        )?;
    } else {
        for line in &answer.selected {
            writeln!(
                out,
                "{}:{} {}",
                parsed.stream.as_str(),
                line.number,
                line.text
            )?;
        }
    }
    Ok(ExitCode::Success)
}

/// What a byte-range read was asked for, as one value.
///
/// A struct rather than four positionals, for [`ShowRequest`]'s reason: the ask is
/// one object, and a list of two `Option<u64>`s beside two booleans is where a
/// caller eventually swaps a pair that both mean "a bound".
#[derive(Debug, Clone, Copy)]
struct RawRequest {
    /// The inclusive start of the byte range, if one was named.
    from: Option<u64>,
    /// The exclusive end of the byte range, if one was named.
    to: Option<u64>,
    /// Write the selection to stdout verbatim — the recorded escape.
    raw: bool,
    /// Emit the selection as a byte-stable base64 document.
    json: bool,
}

/// Read a byte range of a capture — verbatim, or as a base64 document.
///
/// Split out of [`run_capture_show`] because the two produce different things: a
/// line view is text this binary formats, and this is the child's own bytes
/// leaving the process untouched. Keeping them in one function would put a decoded
/// value in scope beside the raw path, which is exactly what `select_raw` exists
/// to avoid.
///
/// **What the raw write bypasses**, stated because each omission is deliberate:
/// `writeln!` (so no trailing newline is added — the one thing every other arm of
/// this verb does), `serde_json::to_string_pretty`, and the whole `output::`
/// ladder. `out` is already a byte sink, so `write_all` is the whole mechanism.
///
/// Rust's `std::io` performs no newline translation on any platform, so there is
/// no `\n` → `\r\n` hazard to guard. The platform claim worth stating is narrower:
/// on Windows a `Stdout` bound to a *console* goes through `WriteConsoleW`, which
/// requires valid UTF-8, and obtaining a true byte handle needs `unsafe` — which
/// the workspace lints forbid. So the verbatim guarantee is a guarantee about a
/// REDIRECTED stdout, which is the only way a program consumes these bytes.
fn run_capture_raw(
    repo: &Path,
    parsed: &capture::Handle,
    asked: RawRequest,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let RawRequest {
        from,
        to,
        raw,
        json,
    } = asked;
    let record = capture::Capture {
        stream: parsed.stream.as_str(),
        bytes: 0,
        digest: parsed.digest.clone(),
    };
    let bytes = capture::read(repo, &record).map_err(|_| {
        UsageError::raise(format!(
            "capture show: no capture at {parsed} — `batten capture list` names the ones this \
             repository holds"
        ))
    })?;
    let answer = capture::select_raw(parsed, &bytes, from, to);
    if raw {
        // THE ESCAPE IS RECORDED WHEN SPENT (CLOUD-1260). This route stays open —
        // a deliberate, single-purpose retrieval is not the failure mode — and it
        // leaves a row, because an unrecorded `--raw` is how a reduction silently
        // stops mattering. Recorded BEFORE the write, so a caller that pipes into
        // something which closes early still leaves the row.
        //
        // Reported and never raised: the retrieval is legitimate and a storage
        // failure must not turn it into an error.
        if let Err(failure) = capture::record_escape(repo, parsed, answer.data.len()) {
            writeln!(
                err,
                "batten: capture show: the escape was not recorded: {failure}"
            )?;
        }
        // The one write in this binary that is not text.
        out.write_all(&answer.data)?;
    } else if json {
        // Base64 rather than an escaped string, because §6 requires the document
        // to be a function of the bytes and a lossy decode is not one; and rather
        // than the bytes themselves, because a `-J` document is parsed by
        // consumers that assume UTF-8.
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "handle": answer.handle,
                "bytes": answer.bytes,
                "from": answer.from,
                "to": answer.to,
                "encoding": "base64",
                "data": base64(&answer.data),
            }))?
        )?;
    } else {
        // Pointer-only by default here too (rule 4): a byte range with neither
        // encoding named reports what it would return, never the payload.
        writeln!(
            out,
            "{} {}..{} {} selected",
            answer.handle,
            answer.from,
            answer.to,
            answer.data.len()
        )?;
    }
    Ok(ExitCode::Success)
}

/// What a resolve-by-key was asked for, as one value.
///
/// A struct rather than five positionals, for [`ClaimAsk`]'s reason: two of them
/// are booleans that both mean "a different encoding of the same selection", and
/// a positional list is where those eventually get swapped.
#[derive(Debug, Clone, Copy)]
struct FindRequest<'a> {
    /// The key the response must carry.
    key: &'a str,
    /// Tool selectors; a response matching any of them is eligible.
    tools: &'a [String],
    /// The dotted path the key sits at, or `None` for the default.
    key_at: Option<&'a str>,
    /// Write the resolved bytes to stdout verbatim — the recorded escape.
    raw: bool,
    /// Emit the pointer as a byte-stable document.
    json: bool,
}

/// The default path a key sits at in a tool response.
///
/// A const rather than a literal at the call site, so the flag's help text and
/// the value it defaults to cannot drift.
const DEFAULT_KEY_AT: &str = "id";

/// `capture find` — resolve a stored response by the key it carries (CLOUD-1121).
///
/// **A miss is exit 1, loudly, and that is the whole anti-vacuity property.** The
/// tempting reading is that finding nothing is a clean answer — the store simply
/// holds no such payload — but every caller here is a gate about to decide over
/// the payload, and a gate handed nothing must report that it could not look. An
/// absent payload read as a clean row is the false green this class produces, so
/// the empty store and the unmatched key both refuse rather than returning a
/// well-formed nothing.
///
/// It never returns [`ExitCode::Violation`]: it renders no policy verdict, and a
/// harness that read "no capture here" as a deny would be reading a fact about a
/// local store as a fact about the repository.
fn run_capture_find(
    repo: &Path,
    asked: FindRequest<'_>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let FindRequest {
        key,
        tools,
        key_at,
        raw,
        json,
    } = asked;
    // `--raw` with `--json` is refused rather than resolved, for the reason
    // `capture show` refuses the pair: a raw byte stream and a byte-stable JSON
    // document are different contracts, and picking one silently is how a caller
    // ends up with base64 where it wanted bytes.
    if raw && json {
        return Err(UsageError::raise(
            "capture find: --raw writes bytes and --json writes a document; name one".to_owned(),
        ));
    }
    let key_at = key_at.unwrap_or(DEFAULT_KEY_AT);
    let selector = capture::Selector { tools, key, key_at };
    let found = capture::find(repo, &selector)?;
    let Some(found) = found else {
        // Pointer-only in the refusal too: the key and the path a caller already
        // typed, the tools they named, and nothing about what the store does
        // hold — a "did you mean" over captured bodies would leak exactly what
        // this verb exists to keep out of context.
        return Err(UsageError::raise(format!(
            "capture find: no complete {} response in this repository's capture store carries \
             {key_at} = {key} — the read has not happened here, or its capture has been pruned",
            tools.join(" or "),
        )));
    };
    if raw {
        // The same non-text write `capture show --raw` makes, and the one route
        // by which a body leaves this verb at all: into a program's stdin.
        //
        // RECORDED WHEN SPENT, for the reason `capture show --raw` is
        // (CLOUD-1260): the two are one escape reached by two addresses, so
        // recording only the handle-addressed one would leave the cheaper route
        // uncounted — which is exactly the shape that made a convention useless.
        let bytes = capture::read(repo, &found.capture)?;
        let handle = capture::Handle::parse(&found.capture.handle())?;
        if let Err(failure) = capture::record_escape(repo, &handle, bytes.len()) {
            writeln!(
                err,
                "batten: capture find: the escape was not recorded: {failure}"
            )?;
        }
        out.write_all(&bytes)?;
    } else if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "handle": found.capture.handle(),
                "bytes": found.capture.bytes,
                "tool": found.tool,
                "order": found.order,
            }))?
        )?;
    } else {
        writeln!(
            out,
            "{} {} bytes {}",
            found.capture.handle(),
            found.capture.bytes,
            found.tool
        )?;
    }
    Ok(ExitCode::Success)
}

/// Everything `batten claim check` was asked for, as one value.
///
/// A struct rather than six parameters, for `ExecRequest`'s reason: the ask is
/// one object and passing it as a list of positionals is where a caller
/// eventually swaps two booleans that both mean "override something".
#[derive(Debug, Clone, Copy)]
struct ClaimAsk<'a> {
    /// The two overrides, which answer different questions and never collapse.
    request: &'a claim::Request,
    /// Re-key a stranded receipt instead of judging a payload.
    adopt: bool,
    /// Which orphan, where more than one is stranded.
    adopt_from: Option<&'a str>,
    /// Resolve the payload from the capture store under this key.
    issue: Option<&'a str>,
    /// Emit the refusals on the structured channel.
    json: bool,
}

/// The repository root, or the working directory where there is none.
///
/// The two board verbs judge a payload rather than a tree, so an unresolvable
/// root is not a refusal — it only means the side effects have nowhere to land.
fn board_root() -> PathBuf {
    git::repo_root(Path::new(".")).unwrap_or_else(|_| PathBuf::from("."))
}

/// Read a caller-supplied evidence file into a key set.
///
/// The first tab-separated field is the key and the second, where present, is
/// whatever the file carries alongside it — a PR number or a ref. A line whose
/// first field is not a key is SKIPPED rather than refused: these files are
/// assembled by callers from forge output, and refusing a stray header would
/// make the gate unrunnable for a reason unrelated to the board.
///
/// Unreadable is [`UsageError`], never an empty set. A caller who named a file
/// this cannot open has not supplied empty evidence, they have supplied evidence
/// nobody read.
fn evidence_file(path: &str, what: &str) -> Result<Vec<(String, Option<String>)>> {
    let raw = std::fs::read_to_string(path).map_err(|_| {
        UsageError::raise(format!(
            "landed: {what} names a file that cannot be read: {path}. That is a caller problem, not a clean board."
        ))
    })?;
    Ok(raw
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let key = fields.next()?.trim();
            if !landed::is_key(key) {
                return None;
            }
            let rest = fields.next().map(|value| value.trim().to_owned());
            Some((key.to_owned(), rest.filter(|value| !value.is_empty())))
        })
        .collect())
}

fn run_landed(
    command: LandedCommand,
    mode: Mode,
    _out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        LandedCommand::Check {
            merged_prs,
            landed_by,
            declined,
        } => run_landed_check(
            merged_prs.as_deref(),
            landed_by.as_deref(),
            declined.as_deref(),
            mode,
            err,
        ),
    }
}

/// Sweep a board for columns that contradict git and the forge.
///
/// # Errors
///
/// [`UsageError`] on every input this cannot read — an unparseable payload, a
/// named file that will not open, and absent `--merged-prs`. That direction is
/// the whole reliability of the gate: a sweep that reported a clean board it
/// never looked at has shipped here twice, and both times the silence was
/// byte-identical to a pass.
fn run_landed_check(
    merged_prs: Option<&str>,
    landed_by: Option<&str>,
    declined: Option<&str>,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // ABSENT EVIDENCE IS COULD-NOT-LOOK, NEVER A SHORT SWEEP. Half the landed
    // disjunction is what merged pull requests closed, and without it the gate
    // would decide on commit trailers alone — which this repository has measured
    // at 3% of its own commits, because fast-forward landing puts the closing
    // key in the PR body.
    let Some(merged_prs) = merged_prs else {
        return Err(UsageError::raise(
            "landed: no --merged-prs evidence, so landedness cannot be decided. Only 3% of this \
             repository's commits carry a closing keyword — fast-forward landing puts it in the PR \
             body — so deciding on commits alone would report a clean column it never checked. \
             Supply `<CLOUD-id><TAB><pr-number>` lines for merged pull requests."
                .to_owned(),
        ));
    };

    let mut payload = String::new();
    std::io::stdin().read_to_string(&mut payload)?;
    if payload.trim().is_empty() {
        return Err(UsageError::raise(
            "landed: stdin is empty; expected get_issue payloads".to_owned(),
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&payload).map_err(|_| {
        UsageError::raise("landed: stdin is not JSON; expected get_issue payloads".to_owned())
    })?;
    let rows = landed::rows_from(&value)?;

    let mut evidence = landed::Evidence::default();
    for (key, _) in evidence_file(merged_prs, "--merged-prs")? {
        evidence.merged.insert(key);
    }
    if let Some(path) = landed_by {
        for (key, reference) in evidence_file(path, "--landed-by")? {
            evidence
                .asserted
                .insert(key, reference.unwrap_or_else(|| "no ref given".to_owned()));
        }
    }
    if let Some(path) = declined {
        for (key, _) in evidence_file(path, "--declined")? {
            evidence.declined.insert(key);
        }
    }

    let report = landed::decide(&rows, &evidence);

    // Pointer-only per rule 4: a key, two column names and a reason class. Never
    // a line of any body — a PR body and an issue body both carry consumer
    // detail, and a sweep that echoed them would leak it through CI logs.
    for finding in &report.findings {
        // WHICH ARM DRAINED IT IS PART OF THE FINDING. A derived landing is
        // evidence; an asserted one is the caller's word, and a reader who
        // cannot tell them apart has to trust the union.
        let suffix = finding
            .asserted_by
            .as_ref()
            .map(|reference| format!("  (asserted by --landed-by: {reference})"))
            .unwrap_or_default();
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "  {}  {} -> {}  {}{suffix}",
                finding.id,
                finding.holds,
                finding.reason.wants(),
                finding.reason.token(),
            ),
        )?;
    }

    if report.is_clean() {
        // ON `err`, NEVER `out`, and the reason is the data channel rather than
        // taste. `out` is the answer and `err` is the messaging (`lib.rs`'s own
        // split), and this row declares `data_channel: true` — so a clean line
        // written to stdout would put prose beside the JSON document and stop
        // `landed check -J` being one pure document, which
        // `every_data_channel_verb_emits_one_pure_json_document` refuses.
        output::message(
            mode,
            Verbosity::Normal,
            err,
            "landed: every column agrees with what git and the forge already did",
        )?;
        return Ok(ExitCode::Success);
    }
    Ok(ExitCode::Violation)
}

fn run_ready(
    command: ReadyCommand,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        // THE RESOLVED REPO ROOT, not the anchor. `hook_authority_root` answers
        // `.` where the config sits in the cwd, and the capture store is keyed by
        // the repository's own directory NAME, which cannot be derived from a
        // relative path — measured as "cannot derive a repository name from .",
        // the same refusal `admission::store_dir` records for the same reason.
        //
        // OUTSIDE A CHECKOUT IT FALLS BACK RATHER THAN REFUSING: both verbs are
        // pure functions of the payload they were handed, and a caller inspecting
        // the board from anywhere still deserves the verdict. Only the side
        // effects — a capture lookup, a receipt — need a repository, and each says
        // so at its own site.
        ReadyCommand::Lint { issue, json } => run_ready_lint(
            &board_root(),
            &board_grammar(overrides)?,
            issue.as_deref(),
            json,
            mode,
            out,
            err,
        ),
    }
}

/// Split a comma-separated roster field, dropping the empties.
///
/// An unset or empty field splits to nothing, which is what makes the STRICT
/// direction reachable by construction rather than by a guard a later edit could
/// forget to keep (CLOUD-337).
fn roster_field(raw: Option<&str>) -> Vec<String> {
    raw.unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

/// Parse one TSV row of a reading. A row that is not five fields is skipped
/// rather than refused, which is how the predecessor read a three-field reading
/// from before the ordering key existed — and answering such a reading exactly
/// as it did then is itself a property (CLOUD-436).
fn parse_run(line: &str) -> Option<checks_green::Run> {
    let mut fields = line.split('\t');
    let status = fields.next()?;
    let conclusion = fields.next()?;
    let name = fields.next()?;
    if name.is_empty() {
        return None;
    }
    Some(checks_green::Run {
        status: status.to_string(),
        conclusion: conclusion.to_string(),
        name: name.to_string(),
        started_at: fields.next().unwrap_or_default().to_string(),
        id: fields.next().unwrap_or_default().parse().unwrap_or(0),
    })
}

fn run_checks(
    command: ChecksCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let ChecksCommand::Green {
        required,
        absent_ok,
        answered,
        fanin,
        json,
    } = command;

    let mut raw = String::new();
    std::io::stdin().read_to_string(&mut raw)?;
    let runs: Vec<checks_green::Run> = raw.lines().filter_map(parse_run).collect();

    let roster = checks_green::Roster {
        required: roster_field(Some(&required)),
        absent_ok: roster_field(absent_ok.as_deref()),
        answered: roster_field(Some(&answered)),
        // An empty `--fanin` is the same as an unset one, and that direction is
        // the safe one: every failure stays manufacturable, which is CLOUD-363's
        // ordering intact.
        fanin: fanin.filter(|name| !name.is_empty()),
    };

    // A roster that cannot decide anything is a statement about the INVOCATION,
    // never about the repository — so `Usage`, and never the policy verdict.
    let verdict = match checks_green::decide(&runs, &roster) {
        Ok(verdict) => verdict,
        Err(problem) => {
            writeln!(err, "::error:: checks green: {problem}")?;
            return Ok(ExitCode::Usage);
        }
    };

    // Pointer-only (rule 4): a `<check> <conclusion>` coordinate and a verdict
    // word, never a run's log. The word is what lets a caller tell "poll again"
    // from "stop" — the distinction the shared exit code deliberately drops.
    // SERDE, NEVER A FORMAT STRING. A check name is forge-supplied text, so a
    // hand-rolled document is one quote away from being unparseable by the
    // caller that asked for JSON — and §6 makes the document a contract.
    let (word, detail, code) = match &verdict {
        checks_green::Verdict::Green => (
            "green",
            "every required check terminal and green".to_owned(),
            ExitCode::Success,
        ),
        checks_green::Verdict::Red(findings) => {
            ("red", render_findings(findings), ExitCode::Violation)
        }
        checks_green::Verdict::Pending(pending) => {
            let detail = match pending {
                checks_green::Pending::Running { pending, graded } => {
                    format!("{pending} required check(s) still running, {graded} graded")
                }
                checks_green::Pending::NoVerdict(findings) => {
                    format!(
                        "required check(s) with no verdict: {}",
                        render_findings(findings)
                    )
                }
                checks_green::Pending::Unregistered(names) => {
                    format!("required check(s) with no run at all: {}", names.join(", "))
                }
            };
            ("pending", detail, ExitCode::Violation)
        }
    };

    if json {
        let document = serde_json::json!({ "verdict": word, "detail": detail });
        writeln!(out, "{document}")?;
    } else {
        writeln!(out, "checks green: {word} — {detail}")?;
    }
    // The annotation is the RED half only: a head that is merely not answered yet
    // is the ordinary state of a fresh SHA, and annotating it would spend
    // `::error::` on the common case until it stops meaning anything (CLOUD-245).
    if matches!(verdict, checks_green::Verdict::Red(_)) {
        writeln!(
            err,
            "::error:: CI is not green — {detail}. Reproduce and fix locally."
        )?;
    }
    Ok(code)
}

/// Dispatch the receipt verbs.
///
/// A named function rather than a `match` inlined into `run`, for the reason
/// every other noun here already has one: the top-level match is a routing
/// table, and a nested arm makes one verb's shape visible in it while every
/// other verb's is not.
fn run_receipt(
    command: ReceiptCommand,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        ReceiptCommand::Record { check } => receipt::run_record(&check, mode, err),
        ReceiptCommand::Status { check, key, json } => receipt::run_status(&check, key, json, out),
    }
}

/// The task registry's reader (CLOUD-425), ported off `mise-tasks/alive.sh`.
///
/// **The exit table is this repository's, not the predecessor's.** `alive.sh`
/// used `2` for "could not look"; here that is `Internal`, because the one
/// contract has one meaning per code and no per-verb exception — `2` is the
/// policy verdict everywhere, and a caller branching on the code alone must not
/// read "I could not tell" as an answer about what is running.
fn run_task(command: TaskCommand, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    // Could-not-look, and never "nothing runs": those are different answers and
    // conflating them is the defect CLOUD-425 exists to fix.
    let Ok(git_dir) = crate::git::git_dir(std::path::Path::new(".")) else {
        writeln!(
            err,
            "::error:: task: not a git repository, so there is no registry"
        )?;
        return Ok(ExitCode::Internal);
    };
    // A registry that cannot be WRITTEN is not an error the caller should die on
    // — a `land` must not fail because its bookkeeping is unwritable — so every
    // write degrades to a no-op and still reports success. Only the READER
    // distinguishes could-not-look, because only it has a verdict to give.
    match command {
        TaskCommand::Register { task, pid, phase } => {
            task::register(
                &git_dir,
                &task,
                &pid,
                phase.as_deref().unwrap_or("starting"),
                boundary_epoch(),
            );
            Ok(ExitCode::Success)
        }
        TaskCommand::Phase { pid, value } => {
            task::push(
                &git_dir,
                &pid,
                task::Signal::Phase,
                &value,
                boundary_epoch(),
            );
            Ok(ExitCode::Success)
        }
        TaskCommand::Tick { pid, value } => {
            task::push(&git_dir, &pid, task::Signal::Tick, &value, boundary_epoch());
            Ok(ExitCode::Success)
        }
        TaskCommand::Sig { pid, value } => {
            task::push(&git_dir, &pid, task::Signal::Sig, &value, boundary_epoch());
            Ok(ExitCode::Success)
        }
        TaskCommand::Unregister { pid } => {
            task::unregister(&git_dir, &pid);
            Ok(ExitCode::Success)
        }
        // A pid that never registered is a READING — invisible, exactly as
        // `alive` reports it — and a caller has to be able to tell it from a
        // field that is legitimately empty, which is why it is a code rather
        // than a blank line. The retiring shell spelled it `1`; the one table
        // spells a record that is not there `2`, and reserves `3` for
        // could-not-look.
        TaskCommand::Read { pid, field } => match task::read_field(&git_dir, &pid, &field) {
            Some(value) => {
                writeln!(out, "{value}")?;
                Ok(ExitCode::Success)
            }
            None => Ok(ExitCode::Violation),
        },
        TaskCommand::Alive {
            program_root,
            instant,
        } => {
            let reading = task::alive(
                &git_dir,
                task::Alive {
                    program_root: &program_root,
                    now: supplied_epoch(instant.as_deref())?,
                },
            );
            task::report(&reading, out, err)
        }
    }
}

/// One task per clone (CLOUD-428), ported off `mise-tasks/singleton.sh`.
fn run_singleton(
    command: SingletonCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // Could-not-look, and never "nothing holds it": reading an unresolvable git
    // dir as free is how a second `land` starts, which is the defect CLOUD-428
    // exists to stop.
    let Ok(git_dir) = crate::git::git_dir(std::path::Path::new(".")) else {
        writeln!(
            err,
            "::error:: singleton: not a git repository, so there is nowhere to hold a lock"
        )?;
        return Ok(ExitCode::Internal);
    };
    match command {
        SingletonCommand::Release { task } => {
            task::singleton_release(&git_dir, &task);
            Ok(ExitCode::Success)
        }
        SingletonCommand::Acquire {
            task,
            pid,
            recheck_ms,
        } => {
            // A malformed interval is a statement about the invocation, never a
            // silent fall back to the default: the pause is the reclaim's whole
            // safety margin, so guessing it would decide a lock silently.
            let recheck = std::time::Duration::from_millis(match recheck_ms {
                Some(raw) => raw.trim().parse::<u64>().map_err(|_| {
                    UsageError::raise("--recheck-ms takes a whole number of milliseconds")
                })?,
                None => 100,
            });
            let claim = task::singleton_acquire(&git_dir, &task, &pid, recheck);
            task::report_claim(&claim, &task, out, err)
        }
    }
}

/// The boundary's own clock, as whole seconds since the epoch.
///
/// A READER at the boundary may take a clock; the decision path may not
/// (`ambient_authority.rs` is the gate on that, and it names `facts.rs`,
/// `rules.rs` and `policy.rs`). What this feeds is a rendered age, never a
/// verdict — and `--instant` is what lets a caller take the clock out even of
/// that, so two calls over one registry state produce identical bytes.
fn boundary_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// The instant a reader measures ages against: supplied, or the boundary's.
///
/// [`supplied_instant`]'s sibling in whole seconds. Separate rather than shared
/// because that one answers in a `SystemTime` for `receipt::verdicts`, and this
/// one in the epoch seconds a registry record is written in — converting between
/// them at the call site would be a second spelling of one value.
fn supplied_epoch(raw: Option<&str>) -> Result<u64> {
    let Some(raw) = raw else {
        return Ok(boundary_epoch());
    };
    raw.trim()
        .parse::<u64>()
        .map_err(|_| UsageError::raise("--instant takes a whole number of seconds since the epoch"))
}

fn run_pr(
    command: PrCommand,
    overrides: &Overrides,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (sha, repo, interval, progress, progress_id, required, absent_ok, answered, fanin) =
        match command {
            PrCommand::Derive { pr } => return run_pr_derive(&pr, overrides, out),
            PrCommand::File { pr } => return run_pr_file(&pr, overrides, mode, out),
            PrCommand::Link { pr, key } => return run_pr_link(&pr, &key, overrides, mode, err),
            PrCommand::Ensure { pr } => return run_pr_ensure(&pr, overrides, mode, err),
            PrCommand::Closes { pr } => return run_pr_closes(&pr, overrides, mode, err),
            PrCommand::Watch {
                sha,
                repo,
                interval,
                progress,
                progress_id,
                required,
                absent_ok,
                answered,
                fanin,
            } => (
                sha,
                repo,
                interval,
                progress,
                progress_id,
                required,
                absent_ok,
                answered,
                fanin,
            ),
        };

    // A NUMBER OR A REFUSAL, never a silent fallback. An interval that did not
    // parse is a typo in an invocation, and swallowing it would put the poll on
    // a cadence nobody asked for — which is exactly the class of defect that is
    // invisible until a rate limit says so.
    let interval = match interval {
        None => pr_watch::DEFAULT_INTERVAL,
        Some(raw) => {
            if let Ok(seconds) = raw.trim().parse::<u64>() {
                seconds
            } else {
                writeln!(
                    err,
                    "::error:: pr watch: --interval takes a whole number of seconds"
                )?;
                return Ok(ExitCode::Usage);
            }
        }
    };

    // BOTH HALVES OR NEITHER. A recorder with nothing to key on would file every
    // landing's signals under one entry, and an identity with no recorder is a
    // caller that thinks it is being observed and is not.
    let progress = match (progress, progress_id) {
        (Some(program), Some(id)) => Some(pr_watch::Progress { program, id }),
        (None, None) => None,
        _ => {
            writeln!(
                err,
                "::error:: pr watch: --progress and --progress-id are one setting; give both or neither"
            )?;
            return Ok(ExitCode::Usage);
        }
    };

    let config = pr_watch::Config {
        sha,
        repo: repo.unwrap_or_else(|| pr_watch::REPO_PLACEHOLDER.to_owned()),
        interval,
        progress,
    };
    let roster = checks_green::Roster {
        required: roster_field(Some(&required)),
        absent_ok: roster_field(absent_ok.as_deref()),
        answered: roster_field(Some(&answered)),
        fanin: fanin.filter(|name| !name.is_empty()),
    };
    pr_watch::watch(&config, &roster, out, err)
}

/// The bot lane this repository declares, or a refusal naming what is missing.
///
/// Absent is a USAGE ERROR rather than a silent skip: a lane assembled from
/// engine defaults would file a row asserting a bump nobody configured, which is
/// the class this whole surface exists to refuse.
fn bot_lane(overrides: &Overrides) -> Result<bot::BotLane> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    config.bot_lane.ok_or_else(|| {
        UsageError::raise(
            "bot lane: this repository declares no [bot_lane] table, so there is no lane to file \
             for — which is a different claim from a lane that owns nothing"
                .to_owned(),
        )
    })
}

/// The candidate row a bot's pull request implies, or a refusal.
///
/// Refuses rather than inventing, which is the whole posture: a PR opened by
/// somebody the lane does not know, or whose diff touches no manifest it owns,
/// gets no row. The alternative is a tracker row asserting a bump nobody
/// proposed.
fn derive_row(lane: &bot::BotLane, number: &str) -> Result<(bot::Pull, String, String)> {
    let pull = bot::forge::pull(&lane.repo, number)?;
    if !bot::is_lane_bot(&pull.login, &lane.bots) {
        return Err(Denial::raise(format!(
            "pr derive: #{number} was opened by '{}', which is not a bot this lane files for — an \
             agent's pull request carries its own claim receipt and its own issue",
            pull.login
        )));
    }
    let files = bot::forge::files(&lane.repo, number)?;
    let owned = bot::owned(&files, &lane.owned_manifests)?;
    if owned.is_empty() {
        // Pointer-only: the paths, never their contents.
        return Err(Denial::raise(format!(
            "pr derive: #{number} touches no manifest this lane owns, so there is no bump to \
             describe: {} — filing a row here would assert a change nobody proposed",
            files.join(" ")
        )));
    }
    // READ from the subject rather than chosen: the bot's own config already
    // decided it. A subject with no prefix is a lane defect, and the commit gate
    // would refuse it anyway, so this says so instead of inventing a type.
    let Some(kind) = bot::conventional_type(&pull.title) else {
        return Err(Denial::raise(format!(
            "pr derive: #{number}'s subject carries no Conventional type, so the commit gate would \
             refuse it and it could never land — fix the bot's configured type rather than filing \
             a row for a commit that cannot merge"
        )));
    };
    let repo_root = git::repo_root(Path::new("."))?;
    let template = std::fs::read_to_string(repo_root.join(&lane.body_template)).map_err(|err| {
        UsageError::raise(format!(
            "bot lane: cannot read body_template {}: {err}",
            lane.body_template
        ))
    })?;
    let manifests = owned
        .iter()
        .map(|path| format!("- `{path}`"))
        .collect::<Vec<_>>()
        .join("\n");
    let body = bot::render(
        &template,
        &[
            ("pr", number.to_owned()),
            ("branch", pull.head.clone()),
            ("login", pull.login.clone()),
            ("manifests", manifests),
            ("type", kind.to_owned()),
        ],
    )?;
    let title = pull.title.clone();
    Ok((pull, title, body))
}

/// `batten pr derive`: the candidate payload, written nowhere.
///
/// The shape is the tracker's own `get_issue` answer, and that is the point: the
/// refinement gate reads it unchanged, so the derived Ready block is checkable by
/// the same gate that checks a human's — which is what keeps "derived" from
/// meaning "exempt".
fn run_pr_derive(number: &str, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let lane = bot_lane(overrides)?;
    // A lane refusal travels as a `Denial`, which the boundary renders and maps to
    // the verdict code — so the refusal path is not caught here. Catching it would
    // put a forge that could not be reached and a pull request the lane declines
    // to file on the same exit code, and those are different claims.
    let (_, title, body) = derive_row(&lane, number)?;
    let payload = serde_json::json!({
        "id": "CLOUD-NEW",
        "status": "Todo",
        "title": title,
        "description": body,
        "pr": number,
        "relations": { "blocks": [], "blockedBy": [], "relatedTo": [] },
    });
    // One encoding, unconditionally: the surface row above declares no `-J` for
    // this verb, so there is no second form for a rung to select.
    writeln!(out, "{}", serde_json::to_string_pretty(&payload)?)?;
    Ok(ExitCode::Success)
}

/// `batten pr file`: open the mirror issue, and report its number.
///
/// THE ROW IS FILED AS A FORGE ISSUE AND THE TRACKER MIRRORS IT (CLOUD-750). The
/// alternative — calling the tracker's API — costs a credential this repository
/// does not hold, and would be the only place in the tree holding one.
///
/// It never CLOSES the mirror, which would move the row to Done: Done means
/// released, so closing would assert a release that has not happened. The pull
/// request closes the tracker key instead, and the merge moves the row exactly as
/// it does for an agent's.
fn run_pr_file(
    number: &str,
    overrides: &Overrides,
    mode: Mode,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let lane = bot_lane(overrides)?;
    let (_, title, body) = derive_row(&lane, number)?;
    let issue = file_mirror(&lane, number, &title, &body)?;
    output::message(
        mode,
        Verbosity::Normal,
        out,
        &format!("pr file: #{number} -> issue #{issue}"),
    )?;
    Ok(ExitCode::Success)
}

/// Open the mirror and answer its number, with the marker appended.
///
/// The marker goes LAST, after the derived block, so it is the one line a reader
/// never has to look at and the one line `ensure` always finds.
fn file_mirror(lane: &bot::BotLane, number: &str, title: &str, body: &str) -> Result<String> {
    let marked = format!("{body}\n\n<!-- {}{number} -->\n", lane.marker_prefix);
    bot::forge::open_issue(&lane.repo, title, &marked)
}

/// `batten pr link`: write the closing key into the pull request's body.
///
/// APPENDED rather than templated in, because the bot rewrites its own body on
/// every rebase and an append survives being reconstructed around.
fn run_pr_link(
    number: &str,
    key: &str,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let lane = bot_lane(overrides)?;
    link(&lane, number, key, mode, err)
}

/// The body rewrite, shared by `pr link` and `pr ensure`.
fn link(
    lane: &bot::BotLane,
    number: &str,
    key: &str,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let pull = bot::forge::pull(&lane.repo, number)?;
    let closing = format!("Closes {key}");
    if pull.body.contains(&closing) {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("pr link: #{number} already closes {key}"),
        )?;
        return Ok(ExitCode::Success);
    }
    bot::forge::set_body(
        &lane.repo,
        number,
        &format!("{}\n\n---\n\n{closing}\n", pull.body),
    )?;
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!("pr link: #{number} now closes {key}"),
    )?;
    Ok(ExitCode::Success)
}

/// `batten pr ensure`: the lander's call — file the row and link it.
///
/// TWO PHASES, BECAUSE THE KEY ARRIVES ASYNCHRONOUSLY. Filing the issue and
/// learning its key are separated by however long the tracker's sync takes, and
/// nothing here may depend on that. So a tick does as much as it can and says
/// what it did; the lander ticks repeatedly and every step is idempotent.
///
/// THAT IS ALSO WHY THIS DOES NOT POLL. A wall-clock wait inside the job would be
/// a guess about somebody else's latency dressed as a mechanism. A tick that
/// cannot finish returns `0` having made progress, and the next one finishes.
fn run_pr_ensure(
    number: &str,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let lane = bot_lane(overrides)?;
    let pull = bot::forge::pull(&lane.repo, number)?;
    // A body that names any key is done, and nothing is filed. The key travels in
    // the body rather than in a local record because the body is what the merge
    // reads — a record this side could go missing and file a second row against a
    // pull request that already has one.
    if let Some(existing) = bot::named_key(&pull.body, &lane.key_prefix) {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("pr ensure: #{number} already names {existing}; nothing filed"),
        )?;
        return Ok(ExitCode::Success);
    }
    let existing = bot::forge::mirror(&lane.repo, number, &lane.marker_prefix)?;
    let issue = if let Some(issue) = existing {
        issue
    } else {
        // `derive_row` refuses a pull request that is not this lane's before
        // anything is written, which is what keeps a refusal from leaving a
        // half-filed row.
        let (_, title, body) = derive_row(&lane, number)?;
        let filed = file_mirror(&lane, number, &title, &body)?;
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "pr ensure: #{number} -> issue #{filed} filed; waiting for the tracker to mirror \
                 it"
            ),
        )?;
        filed
    };
    let comment = bot::forge::linkback(&lane.repo, &issue, &lane.linkback_marker)?;
    let Some(key) = bot::named_key(&comment, &lane.key_prefix) else {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("pr ensure: issue #{issue} is not mirrored yet; the next tick links it"),
        )?;
        return Ok(ExitCode::Success);
    };
    let code = link(&lane, number, &key, mode, err)?;
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!("pr ensure: #{number} -> {key} (via issue #{issue})"),
    )?;
    Ok(code)
}

/// `batten pr closes`: does the body STILL close a key?
///
/// `link` writes the closing key and NOTHING KEEPS IT THERE — a bot regenerates
/// its own body on every rebase and the append goes with it. The lane is nearly
/// right by ordering alone, since `ensure` runs first on each tick, but
/// "normally" is not a gate and the failure inside that window is silent: the
/// fast-forward succeeds, the bump ships, and the row sits in the backlog with
/// nobody looking at it. So the landing asks once more, against the forge rather
/// than against anything it read a step earlier.
///
/// REFUSING IS AN ORDINARY OUTCOME. The next tick re-runs `ensure`, the key comes
/// back, and it lands then. Nothing is lost but the interval.
fn run_pr_closes(
    number: &str,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let lane = bot_lane(overrides)?;
    let pull = bot::forge::pull(&lane.repo, number)?;
    let Some(key) = bot::closing_key(&pull.body, &lane.key_prefix) else {
        // Pointer-only: the number, never the body — a bot pull request carries a
        // release-notes dump, and echoing it would put that in every landing's log.
        output::verdict(
            err,
            &format!(
                "pr closes: #{number}'s body closes no tracker key, so merging it would move \
                 nothing — not landing; the next tick re-links it"
            ),
        )?;
        return Ok(ExitCode::Violation);
    };
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!("pr closes: #{number} closes {key}"),
    )?;
    Ok(ExitCode::Success)
}

/// One `claim bot` refusal: the verdict on stderr and the code that goes with it.
///
/// A function rather than a closure, because a closure capturing `err` holds the
/// mutable borrow for the whole body and the four refusal sites are spread
/// through it.
fn refuse_claim_bot(err: &mut dyn Write, text: &str) -> Result<ExitCode> {
    output::verdict(err, text)?;
    Ok(ExitCode::Violation)
}

/// `batten claim bot`: attest a bot branch from the lane's public facts.
///
/// THE SECOND RECEIPT KIND, AND IT IS SECOND BECAUSE THE TWO ATTEST DIFFERENT
/// THINGS (CLOUD-693, CLOUD-431). `claim check` mints `claim.<branch>`, whose
/// whole content is "a human or agent read this issue, checked it for a
/// competitor, and confirmed the refinement predates this session". Nothing on a
/// bot branch can honestly say that: there was no session, and the row was
/// derived rather than refined. Widening the agent receipt to cover bots would
/// make it mean less everywhere.
///
/// Minted by whoever is at the keyboard, exactly like the agent receipt — the
/// party that ran the check writes the record of it. A workflow minting one would
/// be a receipt asserting a check nobody performed.
fn run_claim_bot(
    repo: &Path,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let lane = bot_lane(overrides)?;
    let Some(branch) = git::current_branch(repo)? else {
        return Err(UsageError::raise(
            "claim bot: a detached HEAD carries no branch to key a receipt to — check the bot \
             branch out by name"
                .to_owned(),
        ));
    };
    if !branch.starts_with(&lane.branch_prefix) {
        return refuse_claim_bot(
            err,
            &format!(
                "claim bot: {branch} is not a bot branch, so the agent claim receipt is the one \
                 that applies here: run `batten claim check` with the issue's payload on stdin"
            ),
        );
    }
    let Some(number) = bot::forge::open_for(&lane.repo, &branch)? else {
        return refuse_claim_bot(
            err,
            &format!(
                "claim bot: no open pull request for {branch} — the receipt attests to facts \
                 about a pull request, so there is nothing to attest"
            ),
        );
    };
    let pull = bot::forge::pull(&lane.repo, &number)?;
    if !bot::is_lane_bot(&pull.login, &lane.bots) {
        return refuse_claim_bot(
            err,
            &format!(
                "claim bot: #{number} was opened by '{}', not by a bot this lane knows",
                pull.login
            ),
        );
    }
    // The same derivation `pr derive` performs, for its refusals rather than its
    // payload: the receipt asserts the diff touches only manifests the lane owns,
    // and that is the check that decides it.
    derive_row(&lane, &number)?;
    let Some(key) = bot::named_key(&pull.body, &lane.key_prefix) else {
        return refuse_claim_bot(
            err,
            &format!(
                "claim bot: #{number}'s body names no tracker row yet — run `batten pr ensure \
                 {number}` first, or wait for the lander's next tick"
            ),
        );
    };
    let attested = bot::Attested {
        key,
        login: pull.login,
        pr: number,
    };
    let receipts = git::git_dir(repo)?.join("batten-receipts");
    let base = git::resolve_ref(repo, "origin/main").ok().flatten();
    bot::mint(
        &receipts,
        &branch,
        &attested,
        base.as_deref(),
        &receipt::rfc3339_utc(now_unix()),
    )?;
    output::message(
        mode,
        Verbosity::Normal,
        out,
        &format!(
            "claim bot: {branch} attested — opened by {}, manifests owned, row {}. `verify` \
             accepts this in place of a claim receipt.",
            attested.login, attested.key
        ),
    )?;
    Ok(ExitCode::Success)
}

/// `batten claim race`: refuse a claim a different open pull request carries.
///
/// The IO half of `mise-tasks/claim-race-check.sh`'s retirement (CLOUD-1422).
/// [`race`] holds the decision and this holds the reads, which is the split the
/// shell could not make — and the split is what makes the defect testable, since
/// the failing case was never about the network.
///
/// **THE ORDER OF THE TWO REFUSALS IS THE WHOLE CORRECTION.** The retired
/// program could not always resolve its own pull request, and its answer to that
/// was to carry on with an empty self — so a branch raced itself. Here an
/// unresolvable self is a *refusal to decide*, not an input to the decision:
/// nothing reaches [`race::races`] until this checkout has been identified in
/// the listing.
///
/// # Everything it cannot establish ALLOWS, and that is unchanged
///
/// No remote, no slug, no forge answer, a truncated listing: each is
/// could-not-look and exits clean with a line saying so. A gate that cannot
/// reach the forge must never become the reason a branch cannot be verified —
/// this runs inside `verify`, where a false red costs the whole pre-flight. What
/// is NOT could-not-look is a listing that came back whole and carries no entry
/// for this head: that is a branch with no open pull request, which has nothing
/// to race.
fn run_claim_race(
    repo: &Path,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let clean = |out: &mut dyn Write, text: &str| -> Result<ExitCode> {
        output::message(mode, Verbosity::Normal, out, text)?;
        Ok(ExitCode::Success)
    };
    let remotes = git::remote_fact(repo)?.remotes;
    let Some(slug) = remotes.get("origin").and_then(|url| race::slug_of(url)) else {
        return clean(
            out,
            "claim race: no origin remote this can derive a repository from — could not look, \
             which is not a verdict",
        );
    };
    let Ok(pulls) = bot::forge::open_pulls(&slug) else {
        return clean(
            out,
            "claim race: the forge did not answer — could not look, which is not a verdict",
        );
    };
    if !bot::forge::open_pulls_are_complete(&pulls) {
        return clean(
            out,
            "claim race: the open pull requests fill a whole page, so a competitor may lie \
             outside it — could not look, which is not a verdict",
        );
    }
    let head = git::head_commit(repo)?;
    let Some(me) = race::identify(&pulls, &head) else {
        return clean(
            out,
            "claim race: no open pull request has this commit as its head, so there is nothing \
             claiming anything yet",
        );
    };
    let grammar = board_grammar(overrides)?;
    let log = bot::forge::commit_messages(&slug, &me.number).unwrap_or_default();
    let mine = race::claimed(&me.head_ref, &me.title, &log, &me.body, &grammar);
    if mine.is_empty() {
        return clean(
            out,
            "claim race: this branch claims no issue — nothing to race",
        );
    }
    let races = race::races(&mine, &pulls, Some(&me.number), &grammar);
    if races.is_empty() {
        return clean(
            out,
            "claim race: no open pull request races this branch's claim",
        );
    }
    for race in &races {
        writeln!(
            err,
            "claim race: {} is already claimed by open pull request #{} ({})",
            race.key, race.number, race.head_ref
        )?;
    }
    writeln!(
        err,
        "claim race: {} claim(s) raced. Two agents on one issue is work that gets thrown away — \
         it has happened here, and the discarded side was already written and verified. Take the \
         frontier from the board rather than a snapshot read at session start; if the competing \
         pull request is stale, say so on the issue and close it rather than racing it.",
        races.len()
    )?;
    Ok(ExitCode::Violation)
}

/// Render findings as the pointer coordinate the predecessor emitted.
fn render_findings(findings: &[checks_green::Finding]) -> String {
    findings
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The Ready grammar, resolved from this repository's own `[[pattern]]` table
/// (CLOUD-1100).
///
/// **The vocabulary is the consumer's and the predicate is the crate's**, which
/// is what keeps a tracker's headings, clause notation and issue keys out of
/// `crates/batten` — non-negotiable rule 1, which CLOUD-1121 broke by carrying
/// eighteen of those tokens in as `const`s.
///
/// A row this repository has not declared is could-not-look, named by id. Never a
/// clause that silently resolves to nothing: a dead gate and a clean tree are
/// byte-identical on the decision surface, and that is the one failure the whole
/// module exists to avoid.
fn board_grammar(overrides: &Overrides) -> Result<ready::Grammar> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    Ok(ready::Grammar::resolve(&config.patterns)?
        .with_prose_threshold(
            config
                .ready
                .as_ref()
                .and_then(|ready| ready.prose_dialect_required_from.clone()),
        )
        .with_pressure_test_threshold(
            config
                .ready
                .as_ref()
                .and_then(|ready| ready.pressure_test_required_from.clone()),
        )
        // THE SUBJECT KIND IS FILTERED HERE, where the config is in hand.
        // A `document` review is the tree surface's — `batten check` reads
        // it off the disk — and a `tracker-body` one has no path to read, so
        // only the second kind can be answered from a refinement payload.
        .with_pressure_test_reviews(
            config
                .rules
                .iter()
                .flat_map(|rule| rule.review.iter())
                .filter(|row| row.subject == "tracker-body")
                .cloned()
                .collect(),
        ))
}

fn run_claim(
    command: ClaimCommand,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        ClaimCommand::Check {
            takeover,
            bypass_sequence,
            adopt,
            adopt_from,
            issue,
            json,
        } => {
            let request = claim::Request {
                takeover,
                bypass_sequence,
            };
            run_claim_check(
                &board_root(),
                &board_grammar(overrides)?,
                &ClaimAsk {
                    request: &request,
                    adopt,
                    adopt_from: adopt_from.as_deref(),
                    issue: issue.as_deref(),
                    json,
                },
                mode,
                out,
                err,
            )
        }
        ClaimCommand::Bot => run_claim_bot(Path::new("."), mode, overrides, out, err),
        ClaimCommand::Race => run_claim_race(Path::new("."), mode, overrides, out, err),
        ClaimCommand::Carry { json } => run_claim_carry(Path::new("."), mode, json, out, err),
    }
}

/// `batten ready lint`: does this issue's Ready block satisfy the checkable
/// clauses?
///
/// **It never asserts that all eight clauses are present**, deliberately. The
/// gate document is explicit that an issue's own body carries only its
/// *specializations*, and the corpus's most thoroughly refined issue omits one
/// clause entirely and is correctly Ready — a lint demanding all eight would fail
/// the best example it has. So: validate the clauses that ARE present, and say
/// nothing about absence.
///
/// # Errors
///
/// [`UsageError`] when the payload cannot be read, when `--issue` resolves
/// nothing, or when the workspace version the §6 arrows depend on is unreadable.
fn run_ready_lint(
    repo: &Path,
    grammar: &ready::Grammar,
    issue: Option<&str>,
    json: bool,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let payload = ready_payload(repo, issue)?;
    let report = ready::lint(grammar, &payload, repo)?;

    // THE DERIVED FACTS GO OUT FIRST, BEFORE ANY VERDICT (CLOUD-806), and the
    // position is the whole of their correctness. They are properties of the
    // BODY rather than of the block: an unrefined row still cites rows, and
    // emitting them after a refusal would make the facts unavailable for exactly
    // the rows most likely to carry a stray citation — which a consumer would
    // then read as "could not look" over a body that was read perfectly well.
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "id": payload.id,
                "emissions": report.emissions,
                "findings": report
                    .findings
                    .iter()
                    .map(|finding| serde_json::json!({
                        "line": finding.line,
                        "rule": finding.rule,
                    }))
                    .collect::<Vec<_>>(),
                "unjudgeable": report.unjudgeable,
            }))?
        )?;
    } else {
        for emission in &report.emissions {
            writeln!(out, "{emission}")?;
        }
    }

    // Pointer-only per rule 4: the line and the rule id, never the prose that
    // matched. Issue bodies can carry consumer detail, and a lint that echoed
    // them would leak it through CI logs.
    for finding in &report.findings {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("{}:{} {}", payload.id, finding.line, finding.rule),
        )?;
    }

    // THE ORDER IS THE RULE (CLOUD-679). A judgeable violation outranks a gap,
    // which is the opposite of the usual "2 outranks 1" and deliberately so: the
    // block is wrong regardless of what could not be seen, and downgrading it to
    // could-not-look would launder a real defect behind a caller's thin fetch.
    // The gap is reported on both arms, so nothing this gate noticed is swallowed.
    if report.unjudgeable > 0 {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "{}:{} unjudgeable-relations",
                payload.id, report.unjudged_line
            ),
        )?;
    }
    if !report.findings.is_empty() {
        return Ok(ExitCode::Violation);
    }
    if report.unjudgeable > 0 {
        // Could-not-look is this verb's own answer and never a verdict: it never
        // prints "satisfies", so no caller can cite this run as a green.
        return Err(UsageError::raise(format!(
            "ready lint: {} cites {} dependenc(ies) and this payload carries no relations key, \
             so neither cross-check could run — refetch with the relations included",
            payload.id, report.unjudgeable
        )));
    }
    if !json {
        // NOT UNDER `-J`. stdout is the data channel there and it carries one
        // document; a human line appended to it makes the document unparseable
        // for the caller that asked for it, which is the whole of §6's purity
        // half.
        output::message(
            mode,
            Verbosity::Normal,
            out,
            &format!(
                "ready lint: {} satisfies the checkable Ready clauses",
                payload.id
            ),
        )?;
    }
    Ok(ExitCode::Success)
}

/// The payload, from the capture store under `--issue` or else from stdin.
///
/// **A failed resolve is could-not-look, never a fall-through to stdin.** The
/// easy implementation keeps reading stdin regardless, and on an empty one it
/// then reports `no-ready-block` — a verdict about the store wearing the costume
/// of a verdict about the issue.
fn ready_payload(repo: &Path, issue: Option<&str>) -> Result<ready::Payload> {
    let Some(key) = issue else {
        let mut body = String::new();
        std::io::stdin().read_to_string(&mut body)?;
        return ready::Payload::parse(&parse_json(&body)?);
    };
    // `get_issue` AND `save_issue`, newest wins (CLOUD-1118): a lint run straight
    // after a write must judge the body the tracker STORED, and the write's own
    // response is the only place that body appears without a second fetch.
    let tools = [READ_TOOL.to_owned(), WRITE_TOOL.to_owned()];
    let selector = capture::Selector {
        tools: &tools,
        key,
        key_at: DEFAULT_KEY_AT,
    };
    let Some(found) = capture::find(repo, &selector)? else {
        return Err(UsageError::raise(format!(
            "ready lint: no stored payload for {key} in this repository's capture store — read \
             the row and the capture mints itself, then run this again"
        )));
    };
    let bytes = capture::read(repo, &found.capture)?;
    let text = String::from_utf8(bytes).map_err(|_| {
        UsageError::raise(format!(
            "ready lint: the stored response for {key} is not UTF-8"
        ))
    })?;
    ready::Payload::parse(&parse_json(&text)?)
}

/// One JSON document, or the could-not-read refusal.
fn parse_json(text: &str) -> Result<serde_json::Value> {
    serde_json::from_str(text).map_err(|_| {
        UsageError::raise(
            "the input is not a get_issue payload with a .description field".to_owned(),
        )
    })
}

/// The tool whose response carries an issue body as read.
const READ_TOOL: &str = "get_issue";

/// And as written — the newest response for a key may be a write's (CLOUD-1118).
const WRITE_TOOL: &str = "save_issue";

/// `batten claim check`: is the issue you are about to pull actually unclaimed?
///
/// # Errors
///
/// [`UsageError`] when the payloads cannot be read, when an issue reaches the
/// readiness rule carrying no body, or when a receipt exists and will not read.
fn run_claim_check(
    repo: &Path,
    grammar: &ready::Grammar,
    ask: &ClaimAsk<'_>,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let ClaimAsk {
        request,
        adopt,
        adopt_from,
        issue,
        json,
    } = *ask;
    let receipts = git::git_dir(repo).ok().map(|dir| dir.join(RECEIPT_DIR));
    if adopt {
        let from = adopt_from;
        // No payload is read: adoption re-keys a claim that was already checked
        // when it was minted, and asking for stdin here would invite a caller to
        // re-assert a verdict this verb is not re-taking.
        return run_claim_adopt(repo, receipts.as_deref(), from, mode, out);
    }

    let issues = claim_payloads(repo, issue)?;
    let verdict = claim::judge(grammar, &issues, request, repo, receipts.as_deref())?;

    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "pullable": verdict.pullable(request),
                "refusals": verdict
                    .refusals
                    .iter()
                    .map(|refusal| serde_json::json!({
                        "id": refusal.id,
                        "rule": refusal.rule,
                        "kind": match refusal.kind {
                            claim::Kind::Competitor => "competitor",
                            claim::Kind::Sequence => "sequence",
                        },
                    }))
                    .collect::<Vec<_>>(),
                "overridden": verdict.overridden,
            }))?
        )?;
    }
    // Pointer-only: the issue id and the rule id, plus a PR number where there is
    // one. Never a body and never a title.
    for refusal in &verdict.refusals {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("{} {}", refusal.id, refusal.rule),
        )?;
    }
    if !verdict.pullable(request) {
        // NAMING WHICH HALF REFUSED, because the remedies are different and
        // offering the wrong one is what shipped the hole CLOUD-816 records: a
        // takeover answers "the competitor is this branch", where a sequence
        // refusal answers "was this story refined before the session implementing
        // it", and a remedy that works for the wrong reason reads as permission.
        let sequence = verdict
            .refusals
            .iter()
            .any(|refusal| matches!(refusal.kind, claim::Kind::Sequence));
        let message = if sequence {
            "claim check: a refinement-sequence refusal above, and --takeover does not clear it. \
             If the honest answer is that you refined this yourself, that decision is \
             --bypass-sequence, which says so in the receipt."
        } else {
            "claim check: not pullable — someone is already on it. Pick another issue, or take \
             it over deliberately with --takeover, which mints the receipt and records what it \
             overrode."
        };
        output::message(mode, Verbosity::Normal, err, message)?;
        return Ok(ExitCode::Violation);
    }

    // Written ONLY here, on the pullable path, which is what makes it a claim
    // rather than a record of an attempt. Outside a checkout the verdict still
    // stands and only the side effect is skipped: a caller inspecting the board
    // from anywhere still deserves the answer.
    if let (Some(receipts), Ok(Some(branch))) = (receipts.as_deref(), git::current_branch(repo)) {
        let base = git::resolve_ref(repo, "origin/main").ok().flatten();
        claim::mint(
            receipts,
            &branch,
            &issues,
            &verdict,
            request,
            base.as_deref(),
            &receipt::rfc3339_utc(now_unix()),
        )?;
    }
    if !json {
        // Not under `-J`, for the reason `ready lint` states: stdout is one
        // document there.
        output::message(
            mode,
            Verbosity::Normal,
            out,
            &format!(
                "claim check: pullable ({} issue(s)) — the receipt is MINTED, for this branch. \
                 Do not run `claim check` again: move Todo -> In Progress and assign yourself, \
                 and stop. A second run arrives after the row has left Todo, reads it as held, \
                 and refuses `not-todo` against your own claim ninety seconds old (CLOUD-1343). \
                 The tracker automation fires on the PR event, which is the end of the work, \
                 not the start.",
                issues.len()
            ),
        )?;
    }
    Ok(ExitCode::Success)
}

/// The `-J` document `claim carry` emits, on either arm.
///
/// One shape for both answers rather than a list on one and an object on the
/// other: a parser that has to branch on the document's TYPE to learn the verdict
/// is reading the exit code twice, and the second reading can disagree.
///
/// Pointer-only per non-negotiable rule 4: a branch, a count, and the refusal id
/// with whatever pointer it carries. Never a licence and never a holder — those
/// are the bytes the table exists to hold.
fn carry_document(branch: &str, carried: usize, refusal: Option<&str>) -> Result<String> {
    Ok(serde_json::to_string_pretty(&serde_json::json!({
        "branch": branch,
        "carried": carried,
        "refusals": refusal.map_or_else(Vec::new, |line| vec![line]),
    }))?)
}

/// `batten claim carry`: does this branch only carry licence rows forward?
///
/// # Why it takes no argument
///
/// The subject is the branch's own diff against its merge base. A caller that
/// could name its own subject could name one that is derivable while changing
/// something else, which is the whole property being attested.
///
/// # Errors
///
/// [`UsageError`] when there is no branch to key a receipt to, or when the merge
/// base or the table cannot be read — could-not-look, never a silent pass.
fn run_claim_carry(
    repo: &Path,
    mode: Mode,
    json: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let Some(branch) = git::current_branch(repo)? else {
        return Err(UsageError::raise(
            "claim carry: a detached HEAD carries no branch to key a receipt to".to_owned(),
        ));
    };
    let Some(base) = git::merge_base(repo, "origin/main")? else {
        return Err(UsageError::raise(
            "claim carry: no merge base with origin/main, so there is nothing to carry against"
                .to_owned(),
        ));
    };

    // The table on each side. An absent base copy reads as empty, which the
    // predicate then refuses as `no-prior-row` rather than admitting a first row
    // that vouches for itself.
    let before = match git::read_at(repo, &base, carry::TABLE)? {
        git::BaseBlob::Found { text, .. } => text,
        git::BaseBlob::AbsentAtRef { .. } | git::BaseBlob::RefUnreachable { .. } => String::new(),
    };
    let after = std::fs::read_to_string(repo.join(carry::TABLE)).unwrap_or_default();

    // Every OTHER path this branch moved. `writes_in_range` answers per commit
    // over declared globs, so `**` is the whole tree and the table is filtered out
    // here — one differ, rather than a second opinion about what changed.
    let mut other: Vec<String> = Vec::new();
    for write in git::writes_in_range(repo, &base, "HEAD", &["**".to_owned()])? {
        for path in write.paths {
            if path != carry::TABLE && !other.contains(&path) {
                other.push(path);
            }
        }
    }
    other.sort();

    match carry::judge(&before, &after, &other) {
        Ok(carried) => {
            let receipts = git::git_dir(repo)?.join("batten-receipts");
            let at = receipt::rfc3339_utc(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_secs()),
            );
            carry::mint(&receipts, &branch, carried, Some(base.as_str()), &at)?;
            if json {
                writeln!(out, "{}", carry_document(&branch, carried, None)?)?;
            } else {
                // On STDOUT and gated on `-J`, for `claim check`'s reason one
                // function up: stdout is one document under the data channel, and a
                // summary on stderr is progress — which the output contract admits
                // only when a rung asked for it.
                output::message(
                    mode,
                    Verbosity::Normal,
                    out,
                    &format!(
                        "claim carry: {branch} carries {carried} licence row(s) forward and \
                         nothing else — `verify` accepts this in place of a claim receipt."
                    ),
                )?;
            }
            Ok(ExitCode::Success)
        }
        Err(refusal) => {
            let line = refusal.line();
            if json {
                writeln!(out, "{}", carry_document(&branch, 0, Some(&line))?)?;
            } else {
                writeln!(out, "{line}")?;
            }
            output::verdict(
                err,
                "claim carry: this branch is not a licence carry, so no receipt is minted. A \
                 carry appends rows whose repo the base table already maps, changing only the \
                 sha, and touches nothing else.",
            )?;
            Ok(ExitCode::Violation)
        }
    }
}

/// Re-key a stranded claim receipt onto this branch.
fn run_claim_adopt(
    repo: &Path,
    receipts: Option<&Path>,
    from: Option<&str>,
    mode: Mode,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let Some(receipts) = receipts else {
        return Err(UsageError::raise(
            "claim check: --adopt needs a git checkout".to_owned(),
        ));
    };
    let Some(branch) = git::current_branch(repo)? else {
        return Err(UsageError::raise(
            "claim check: --adopt needs a branch; HEAD is detached, and a detached HEAD has no \
             name to key a claim on"
                .to_owned(),
        ));
    };
    let lives = |name: &str| {
        git::resolve_ref(repo, &format!("refs/heads/{name}"))
            .ok()
            .flatten()
            .is_some()
    };
    let orphan = claim::adopt(receipts, &branch, from, &lives)?;
    output::message(
        mode,
        Verbosity::Normal,
        out,
        &format!(
            "claim check: adopted the claim receipt from \"{}\" onto \"{branch}\", recorded in \
             the receipt",
            orphan.recorded
        ),
    )?;
    Ok(ExitCode::Success)
}

/// The payloads, from the capture store under `--issue` or else from stdin.
///
/// Accepts either a JSON array or a single object, so a caller can pipe what the
/// tracker returned without reshaping it.
fn claim_payloads(repo: &Path, issue: Option<&str>) -> Result<Vec<claim::Issue>> {
    let value = if let Some(key) = issue {
        let tools = [READ_TOOL.to_owned(), WRITE_TOOL.to_owned()];
        let selector = capture::Selector {
            tools: &tools,
            key,
            key_at: DEFAULT_KEY_AT,
        };
        let Some(found) = capture::find(repo, &selector)? else {
            return Err(UsageError::raise(format!(
                "claim check: no stored payload for {key} in this repository's capture store"
            )));
        };
        let bytes = capture::read(repo, &found.capture)?;
        let text = String::from_utf8(bytes).map_err(|_| {
            UsageError::raise(format!(
                "claim check: the stored response for {key} is not UTF-8"
            ))
        })?;
        serde_json::from_str::<serde_json::Value>(&text)
    } else {
        let mut body = String::new();
        std::io::stdin().read_to_string(&mut body)?;
        serde_json::from_str::<serde_json::Value>(&body)
    }
    .map_err(|_| {
        UsageError::raise(
            "the input is not a set of get_issue payloads (need id and status per issue)"
                .to_owned(),
        )
    })?;
    let values = match value {
        serde_json::Value::Array(items) => items,
        other => vec![other],
    };
    if values.is_empty() {
        return Err(UsageError::raise(
            "the input is not a set of get_issue payloads (need id and status per issue)"
                .to_owned(),
        ));
    }
    values.iter().map(claim::Issue::parse).collect()
}

/// The out-of-tree receipt directory both halves of the claim protocol share.
const RECEIPT_DIR: &str = "batten-receipts";

/// Seconds since the epoch, or zero where the clock will not read — a timestamp
/// nobody can produce is recorded as one rather than refusing the claim.
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Standard base64, unpadded-free (RFC 4648 with `=` padding).
///
/// ~20 lines rather than a dependency: `deny.toml` and
/// `tests/ambient_authority.rs` both price a new crate in the supply chain as a
/// decision to be argued, and this is the only base64 in the tool.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = chunk.get(1).copied().map_or(0, u32::from);
        let b2 = chunk.get(2).copied().map_or(0, u32::from);
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let indices = [
            (triple >> 18) & 0x3F,
            (triple >> 12) & 0x3F,
            (triple >> 6) & 0x3F,
            triple & 0x3F,
        ];
        for (position, index) in indices.iter().enumerate() {
            // The last chunk pads: two source bytes drop the final character and
            // one source byte drops the final two.
            if position > chunk.len() {
                encoded.push('=');
            } else {
                encoded.push(char::from(ALPHABET[*index as usize]));
            }
        }
    }
    encoded
}

/// List this repository's captures as handles, or its recorded calls.
///
/// Two views over one store, on the two axes CLOUD-917 keeps separate: the blob
/// listing answers "which bytes does this repository hold", and `--calls` answers
/// "which calls happened". Dedup collapses the first and never the second, so
/// forty calls that printed the same thing are one line in the blob view and
/// forty in this one — which is the whole reason provenance is a second record.
///
/// Both orderings are byte-stable (§6) and neither reads an mtime. The call view
/// never renders `seen_at`, because a listing that printed a timestamp would stop
/// agreeing with itself across runs.
fn run_capture_list(
    repo: &Path,
    stream: Option<&str>,
    calls: bool,
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    if calls {
        let recorded = capture::calls(repo)?;
        if json {
            writeln!(out, "{}", serde_json::to_string_pretty(&recorded)?)?;
        } else {
            for row in &recorded {
                // Pointer-only: a handle or a reason id, the host, the event and
                // the ordinal. Never bytes, never a path, never the timestamp.
                let names = match (&row.digest, &row.absent) {
                    (Some(digest), _) => format!("response:{digest}"),
                    (None, Some(reason)) => format!("absent:{reason}"),
                    (None, None) => "absent:unrecorded".to_owned(),
                };
                writeln!(
                    out,
                    "{names} {} {} {} #{}",
                    row.source, row.host, row.event, row.order
                )?;
            }
        }
        return Ok(ExitCode::Success);
    }
    if let Some(stream) = stream {
        // Validated through the handle parser rather than a second list of stream
        // names, so the filter cannot come to disagree with the store about what a
        // stream is. The `00` is a throwaway digest: only the stream is judged.
        capture::Handle::parse(&format!("{stream}:00"))?;
    }
    let held: Vec<capture::Capture> = capture::list(repo)?
        .into_iter()
        .filter(|record| stream.is_none_or(|want| record.stream == want))
        .collect();
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&held)?)?;
    } else {
        for record in &held {
            writeln!(out, "{} {} bytes", record.handle(), record.bytes)?;
        }
    }
    Ok(ExitCode::Success)
}

/// Remove this repository's captures — the one removal path.
fn run_capture_prune(
    repo: &Path,
    yes: bool,
    dry_run: bool,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    if dry_run {
        let held = capture::list(repo)?.len();
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            &format!("capture prune: would remove {held} capture(s)"),
        )?;
        return Ok(ExitCode::Success);
    }
    if !yes {
        // §4's refusal, and unconditional rather than only-when-unattended on
        // purpose: the same section says a policy engine that blocks a loop
        // waiting for a Y/N is a dead gate, and the primary caller here is a
        // program. Naming the flag is the whole remedy, which is what makes the
        // refusal one hop from done rather than a wall.
        return Err(UsageError::raise(
            "capture prune: removing captures is destructive and this never prompts — pass -y, \
             or -n to see what would go",
        ));
    }
    let removed = capture::prune(repo)?;
    output::message(
        mode,
        output::Verbosity::Normal,
        err,
        &format!("capture prune: removed {removed} capture(s)"),
    )?;
    Ok(ExitCode::Success)
}

/// The one write path over a host's hook registrations, and the only verb whose
/// subject is outside the repository — which is why it is `destructive` and why
/// it records before it repairs (CLOUD-893).
///
/// A dispatcher rather than a direct arm in [`run`], for `run_capture`'s reason:
/// that table is one line per verb, and `run` is at its line ceiling.
///
/// # Errors
///
/// Whatever the chosen sub-verb could not do.
fn run_wiring(command: &cli::WiringCommand, mode: Mode, err: &mut dyn Write) -> Result<ExitCode> {
    match command {
        cli::WiringCommand::Reclaim {
            yes,
            dry_run,
            check,
        } => run_wiring_reclaim(*yes, *dry_run, *check, mode, err),
    }
}

/// Remove every non-batten hook registration from this host's merged surfaces.
///
/// **`ExitCode::Success` even when it found nothing**, and even when it removed
/// something. This is a repair, not a check: `doctor hooks` answers *is there a
/// hook here that is not mine* and the consumer's gate turns that into a verdict,
/// so an exit code here would be a second authority for the same question — and
/// per §7 a `2` from a repair would read to a mediating harness as a deny.
///
/// **Output on stderr, and a count rather than a name** (non-negotiable rule 4).
/// What was removed is a filename off somebody's home directory; the arithmetic
/// is the actionable part and the harness plus event is where to look.
///
/// # Errors
///
/// A [`UsageError`] without `-y`, and whatever [`wiring::reclaim`] could not
/// write.
fn run_wiring_reclaim(
    yes: bool,
    dry_run: bool,
    check: bool,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    use etcetera::BaseStrategy as _;

    // `--check` IS `--dry-run` plus an exit code, and reusing the computation is
    // what stops the two answers from being able to disagree. A separate walk
    // would be a second authority over "is a repair owed" — the class this
    // repository has measured twice.
    let dry_run = dry_run || check;

    // `hook_authority_root`, NOT `git::repo_root` — and the difference is a linked
    // worktree, which is CLOUD-824's defect one layer over. `reclaim` derives the
    // at-load record path from this argument, and the only thing that EXPIRES that
    // record is `expire_wiring_record`, which reads `hook_authority_root()`.
    // `anchor` answers `.` whenever `batten.toml` sits beside the caller, where
    // `repo_root` answers the MAIN repository's root; from a linked worktree those
    // are two different git directories. So the pair would disagree: the repair
    // writes a record the next `SessionStart` never clears, and `doctor hooks`
    // stays red over a repair that already happened — the manufactured red that is
    // this record's own false-green failure mode, inverted.
    //
    // Safe against the other use of this argument: `reclaim` also compares each
    // merged surface against `dir.join(surface)` through `same_file`, which
    // canonicalizes both sides, so a relative `.` and an absolute root resolve
    // identically there.
    let repo = hook_authority_root();
    if !dry_run && !yes {
        // §4's refusal, unconditional for `capture prune`'s reason: the same
        // section says a policy engine that blocks a loop waiting for a Y/N is a
        // dead gate, and the primary caller here is a program. Naming the flag is
        // the whole remedy.
        return Err(UsageError::raise(
            "wiring reclaim: removing another tool's hook registrations is destructive and this \
             never prompts — pass -y, or -n to see what would go",
        ));
    }
    // No resolvable home is COULD NOT LOOK, and it is a usage error rather than a
    // silent zero: a repair that reports "removed 0" having looked nowhere is the
    // false green this whole capability is built to refuse.
    let strategy = etcetera::choose_base_strategy().map_err(|_| {
        UsageError::raise(
            "wiring reclaim: no home directory resolves, so there are no merged surfaces to read",
        )
    })?;
    let done = wiring::reclaim(repo, strategy.home_dir(), dry_run)?;
    let verb = if dry_run || !done.authoritative {
        "would remove"
    } else {
        "removed"
    };
    output::message(
        mode,
        output::Verbosity::Normal,
        err,
        &format!(
            "wiring reclaim: {verb} {} sibling registration(s) across {} surface(s) read",
            done.siblings(),
            done.surfaces_read
        ),
    )?;
    for row in &done.rows {
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            &format!(
                "wiring reclaim: {}:{} {} {}",
                row.harness, row.event, verb, row.siblings
            ),
        )?;
    }
    // WHY IT REMOVED NOTHING, when it found something and was not asked to look
    // only (CLOUD-1383). A conservative run that stays silent here is the
    // could-not-look-as-clean shape one layer over: the operator asked for a
    // repair, the verb reported siblings, nothing changed, and nothing said why.
    //
    // Emitted only when there was something to act on. A machine with no siblings
    // needs no explanation of a removal that was never owed.
    if !dry_run && !done.authoritative && done.siblings() > 0 {
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            "wiring reclaim: this environment is not declared disposable, so nothing was \
             removed — these registrations are somebody's own. Set BATTEN_ENVIRONMENT=disposable \
             where the home directory is provisioned per session and may be taken.",
        )?;
    }
    // The line that stops the repair reading as completion. Emitted only when
    // something actually moved, because a run that removed nothing left no gap
    // between what this session loaded and what is on disk.
    if !dry_run && done.authoritative && done.siblings() > 0 {
        output::message(
            mode,
            output::Verbosity::Normal,
            err,
            "wiring reclaim: this session already loaded the wiring that was just removed — \
             restart the harness before reading `doctor hooks` as green",
        )?;
    }
    // THE ONE PLACE THIS VERB DECIDES. Bare and `--dry-run` are both `Success`
    // whatever they found, deliberately — a repair is not a check, and `doctor
    // hooks` answers the *is there a sibling* question as a count because
    // whether one is legitimate is a consumer's judgement. `--check` is where a
    // consumer has already made that judgement, in a `[[startup]]` row, and is
    // asking for the same walk as an exit code.
    //
    // `Usage`, never `Violation`: a merged surface carrying somebody else's hook
    // is the config-or-usage class, and a mediating harness reading `2` as a
    // policy denial must not be told this is one (§7).
    Ok(if check && done.siblings() > 0 {
        ExitCode::Usage
    } else {
        ExitCode::Success
    })
}

/// One half of a `FROM:TO` range, as a 1-indexed line number.
///
/// Strict on both halves: a range with a missing or unparseable side is a
/// [`UsageError`] naming the shape, never a silent default. Defaulting the end to
/// the capture's length would make `--lines 5:` mean "the rest" without anyone
/// declaring it, and defaulting the start to 1 would turn a typo into a full dump
/// — the exact cost this verb exists to avoid.
fn parse_line(range: &str, half: usize) -> Result<usize> {
    let bad = || {
        UsageError::raise(format!(
            "capture show: {range:?} is not a line range — write `FROM:TO`, both 1-indexed"
        ))
    };
    let (from, to) = range.split_once(':').ok_or_else(bad)?;
    let chosen = if half == 0 { from } else { to };
    let value: usize = chosen.trim().parse().map_err(|_| bad())?;
    if value == 0 {
        return Err(UsageError::raise(format!(
            "capture show: line numbers are 1-indexed, so {range:?} has no line 0"
        )));
    }
    Ok(value)
}

/// A `FROM:TO` byte range: 0-indexed, half-open, either half omittable.
///
/// **Deliberately laxer than [`parse_line`] about an EMPTY half and exactly as
/// strict about a malformed one**, and the divergence is declared rather than
/// inherited. `parse_line` refuses `5:` because defaulting the end would make it
/// mean "the rest" without anyone saying so — the range is inclusive, so there is
/// no notation for an open end and a caller could not have meant one. A byte range
/// is half-open, so an absent bound is the *only* way to say "to the end" without
/// first learning the length, and reading it as such invents nothing.
///
/// Three refusals, worded apart so a caller can tell them from each other: no
/// separator, a non-numeric half, and a half that overflows `u64`. The last is
/// separate because "too big" and "not a number" have different fixes.
///
/// **It never compares against a length**, because it has none — an out-of-range
/// but well-formed bound is clamped, and the clamp lives in
/// [`capture::select_raw`] and only there.
fn parse_bytes(range: &str) -> Result<(Option<u64>, Option<u64>)> {
    let shape = || {
        UsageError::raise(format!(
            "capture show: {range:?} is not a byte range — write `FROM:TO`, 0-indexed, `FROM` \
             inclusive and `TO` exclusive; either side may be omitted"
        ))
    };
    let (from, to) = range.split_once(':').ok_or_else(shape)?;
    let half = |text: &str, side: &str| -> Result<Option<u64>> {
        let text = text.trim();
        if text.is_empty() {
            return Ok(None);
        }
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(UsageError::raise(format!(
                "capture show: the {side} bound {text:?} is not a number — a byte offset is \
                 decimal digits"
            )));
        }
        text.parse::<u64>().map(Some).map_err(|_| {
            UsageError::raise(format!(
                "capture show: the {side} bound {text:?} is larger than {} — no capture is that \
                 long",
                u64::MAX
            ))
        })
    };
    Ok((half(from, "start")?, half(to, "end")?))
}

/// List what the store holds.
///
/// **Always [`ExitCode::Success`].** A stored finding is a record, not a fresh
/// verdict — `check` already spent the `2` when it found the thing. Emitting a
/// violation here would put the store on the deny channel and let a stale record
/// block a call, which is exactly the interaction law the identity module
/// states: identity governs advisory reporting and never touches an exit path.
fn run_state_list(
    json: bool,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        // Nothing bound yet: an empty listing, not an error. The note rides the
        // §3 ladder above `normal` rather than being written directly — an
        // unbound store is an ordinary first-run state, and a read verb's clean
        // piped run prints nothing unless the caller asked for detail.
        output::message(
            mode,
            output::Verbosity::Verbose,
            err,
            "no store is bound to this repository yet",
        )?;
        if json {
            writeln!(out, "{}", serde_json::to_string_pretty(&Vec::<u8>::new())?)?;
        }
        return Ok(ExitCode::Success);
    };
    let records = findings::load_all(&dir)?;
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&records)?)?;
    } else {
        for line in findings::pointer_lines(&records) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Report every declared file-set budget (CLOUD-50).
///
/// The **introspection** surface, not the enforcement one — enforcement is a
/// finding on `check`, so a budget bites without anybody choosing to look.
///
/// A config declaring no budget at all is a **usage error**, not a silent pass.
/// A budget verb run against a config that declares no budget measured nothing,
/// and reporting that as `0` would be the false green this engine exists to
/// catch — the same reading `rules::run_static` gives a rule it cannot honestly
/// run. (`check` reads the same absence the other way, and both are right: see
/// [`budget::measure_all`].)
fn run_budget(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let declared = config.budget.as_ref().ok_or_else(|| {
        UsageError::raise(format!(
            "no [budget.<name>] in {}; there is no budget to judge",
            config::CONFIG_FILE
        ))
    })?;
    let reports = budget::measure_all(Path::new("."), Some(declared))?;
    let over = reports.iter().any(budget::Report::over_budget);

    if json {
        // Emitted unconditionally, including for a run within budget: JSON that
        // is sometimes absent is unparseable. An array because there are N sets;
        // one set is an array of one, not a bare object, so the shape does not
        // change under the consumer as they add a second budget.
        writeln!(out, "{}", serde_json::to_string_pretty(&reports)?)?;
    } else {
        // Silence is the success signal on the human channel (§6), so a set's
        // per-file breakdown is written only when it explains a verdict.
        for report in reports.iter().filter(|report| report.over_budget()) {
            output::lines(out, &report.files)?;
            output::line(out, report)?;
        }
    }
    Ok(ExitCode::verdict(over))
}

/// The reason tokens `policy test` reports with.
///
/// Named constants rather than literals at the call site, because these are the
/// verb's stable vocabulary: a caller greps for them and `tests/policy_test.rs`
/// asserts on them, so a reworded string is a broken contract rather than a
/// cosmetic change. Same shape `doctor::WiringReport` uses for its findings.
const FIXTURE_MISSING: &str = "fixture-missing";
const TEST_FAILED: &str = "test-failed";
const PREDICATE_UNEXERCISED: &str = "predicate-unexercised";
const MODULE_UNTESTED: &str = "module-untested";
/// A mediated-call module whose every `test_` rule passes a bare command
/// (CLOUD-857). Named for the DEFECT rather than the remedy, like its two
/// neighbours: what is wrong is that the tests only ever saw a bare command.
const MODULE_BARE_ONLY: &str = "module-tested-bare-only";
const SUITE_NOT_RUN: &str = "suite-not-run";

/// One bundle's suite, as the `-J` document renders it (CLOUD-835).
///
/// **One shape, always.** Every key is present on every run, including a clean
/// one and one whose suite never ran — a document whose keys come and go is
/// unparseable. Degrade the VALUE, never the shape, the same rule
/// `AttributionDocument` keeps.
///
/// Field order is struct order rather than a map's, so the emission is
/// byte-stable (§6). Pointer-only (rule 4): module paths, rule names, predicate
/// ids and counts — never a fixture's contents and never a byte of policy body.
#[derive(serde::Serialize)]
struct SuiteReport {
    /// The row that registered this bundle.
    bundle: String,
    /// Whether the suite ran at all. `false` makes every list below vacuous
    /// rather than clean, which is the distinction CLOUD-251 exists for.
    looked: bool,
    /// Declared documents the tree does not carry.
    missing: Vec<String>,
    /// Tests that evaluated to `true`.
    passed: Vec<policy::TestId>,
    /// Tests that did not — `false` and undefined alike.
    failed: Vec<policy::TestId>,
    /// Published predicate ids no test caused to be entered.
    unexercised: Vec<String>,
    /// Module paths carrying no `test_` rule at all.
    untested_modules: Vec<String>,
    /// Mediated-call module paths whose every `test_` rule passes a bare
    /// command (CLOUD-857).
    bare_only_modules: Vec<String>,
}

impl SuiteReport {
    /// A suite that could not run at all, for the row named.
    ///
    /// Constructed rather than defaulted so the `looked: false` is written once:
    /// a report assembled field-by-field at three call sites is how one of them
    /// eventually says `true` about a run that did not happen.
    fn not_run(bundle: &str, missing: Vec<String>) -> Self {
        Self {
            bundle: bundle.to_owned(),
            looked: false,
            missing,
            passed: Vec::new(),
            failed: Vec::new(),
            unexercised: Vec::new(),
            untested_modules: Vec::new(),
            bare_only_modules: Vec::new(),
        }
    }
}

/// Run each registered module's own `test_` rules (CLOUD-835).
///
/// **The gap this closes.** `crates/batten/tests/it/policy_modules.rs` exercises
/// the *evaluator*; nothing exercises a *module*. That is a blocker rather than
/// a nicety because the retirement campaign has to move 1,570 of 2,485 bats
/// cases onto policy rows, and CLOUD-202 measured the trap that makes an
/// untested port worse than none — the shell tasks spell `1 = violation,
/// 2 = could not read` and this contract is the exact inverse.
///
/// **The fixture is the row's own `documents`.** No new config key: CLOUD-833
/// already gave a tree-scoped policy row the documents it hands its bundle, and
/// `rules::tree_document` already parses them and returns the ones the tree does
/// not carry rather than guessing. Non-negotiable 6 keeps configuration narrow,
/// and this is the reuse that honours it.
///
/// # Exit codes, and the two faults kept apart
///
/// `2` when a test failed or a published predicate went unexercised — the row's
/// §7(b) is explicit that the latter is *"reported, not green"*. `1` when the
/// suite could not run: a declared fixture the tree does not carry, or a sweep
/// that did not happen. Separating them is CLOUD-202's whole lesson, and
/// `tests/policy_test.rs` asserts each independently so the port cannot
/// reintroduce the inversion it exists to avoid.
///
/// # Errors
///
/// A [`UsageError`] (exit `1`) when the config will not resolve or a registered
/// module will not load — both refused by [`policy::load`] with their own
/// message, at the boundary where a config fault belongs.
/// The tree input one policy suite runs against.
///
/// Split out of [`run_policy_test`] so that function reads as a loop over rows;
/// what it holds is the pair of deliberate omissions, which are easier to see
/// stated together than buried in an argument list.
///
/// **A SUITE RUNS AGAINST NO PRODUCED RECORD** (CLOUD-851). A module's tests must
/// decide the same way on every machine, and the sink store is per-checkout state
/// that differs between them — so a test that wants a baseline supplies it with
/// `with input as`, the same way a mediated-call suite supplies its call.
///
/// **AND AGAINST NO GIT FACT**, for exactly the same reason (CLOUD-907). HEAD, the
/// branch, the remotes and whether a ref resolves are all per-checkout state: a
/// suite that read them would pass on the author's machine and fail in CI's
/// detached, remote-less clone, which is a test asserting its environment rather
/// than its module.
fn suite_input(
    rule: &rules::Rule,
    documents: &std::collections::BTreeMap<(String, rules::Wanted), rules::Acquired>,
    tracked: &[String],
) -> Result<(String, Vec<(String, rules::NotAcquired)>)> {
    // A mediated-call row declares no documents, so its tests run against `{}`
    // and supply their own input with `with input as` — OPA and Conftest's own
    // shape, and the reason neither surface needs a fixture key.
    Ok(rules::tree_document(
        documents,
        &rules::Declared {
            documents: &rules::declared_documents(rule, tracked)?,
            lines: &rules::declared_lines(rule, tracked)?,
            invocations: &rules::declared_invocations(rule, tracked)?,
            uses: &rules::declared_uses(rule, tracked)?,
            // EMPTY, unlike its neighbours above, and the asymmetry is the
            // point (CLOUD-1167). `documents` and the three beside it name paths
            // INSIDE the repository, so a declared one that is missing is a
            // fixture the author owes. An `[[rule.external]]` row names a file
            // outside it — a launcher's settings, a toolchain's data directory —
            // which is legitimately absent on a CI runner, in a fresh container,
            // and on any host that does not run that launcher. Resolving the
            // declared list here would report every such host as a missing
            // fixture and fail `policy test` for a file the module's own `test_`
            // rules never read: they supply their input with `with input as`,
            // which is what this call is building the SHAPE for.
            //
            // Whether a declared out-of-root file actually resolves is `check`'s
            // question, and `check` answers it the way the family requires — the
            // id goes to `input.tree.missing` with its cause and the row is
            // skipped, rather than running against a fabricated empty document.
            // EMPTY for `external`'s reason: a staged read needs an index this
            // shape-building call has no reason to open.
            staged: &[],
            // Nothing to fall back FOR: the list above is empty, so no path ever
            // reaches the extension test this would answer.
            staged_format: None,
            external: &[],
        },
        tracked,
        // A module's own `test_` rules supply their input with `with input as`,
        // so every member here is empty for one reason: this call builds the
        // SHAPE, and the case chooses the values.
        &rules::Resolved {
            review: &crate::facts::Look::IsNot,
            produced: &std::collections::BTreeMap::new(),
            records: &std::collections::BTreeMap::new(),
            records_blocked: &std::collections::BTreeMap::new(),
            git: &git::GitFacts::default(),
            symbols: &facts::Look::IsNot,
            external: &std::collections::BTreeMap::new(),
            state: None,
            forge: None,
            tool_verdicts: None,
            minted: None,
            captured: None,
        },
    ))
}

/// Print the tool names the `mediated_call` rows decide (CLOUD-312 row 4).
///
/// # Why the engine publishes this
///
/// A consumer's permission file may deny a tool on a host-supplied connector, and
/// the host chooses that connector's exposed name per registration episode — so a
/// deny naming one spelling enforces nothing the moment it comes back under
/// another (CLOUD-178). What rescues such a rule is something matching the tool by
/// SUFFIX, which is exactly what a `tool`-keyed row does.
///
/// A consumer gate therefore has to know which names the table decides. That fact
/// used to be a flag on the guard that decided them; retiring the guard into rows
/// would have left the gate grepping `batten.toml`, which is a second authority
/// for a fact the loader already holds. So the engine answers it.
///
/// # Output
///
/// One name per line, sorted and deduplicated, or a byte-stable JSON array under
/// `-J`. A name is a selector out of the committed config — the consumer's own
/// vocabulary, echoed back — and never a payload, so this is pointer-shaped by
/// construction (non-negotiable rule 4).
fn run_policy_tools(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let root = Path::new(".");
    let config = resolve::resolve(root, overrides)?;
    // A `BTreeSet` rather than a sort at the end: the dedupe and the order are one
    // decision, and §6's byte-stability is what both are for.
    let names: std::collections::BTreeSet<&str> = config
        .rules
        .iter()
        .filter(|rule| rule.scope == rules::RuleScope::MediatedCall)
        .filter_map(|rule| rule.tool.as_deref())
        .collect();
    if json {
        let document = serde_json::json!({ "tools": names.iter().collect::<Vec<_>>() });
        writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
    } else {
        for name in &names {
            writeln!(out, "{name}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Resolve a verdict token to its class definition and routes (CLOUD-1053).
///
/// # The hot path got shorter and this is where the rest went
///
/// A refusal now prints a token, a one-line gloss and a pointer. That is the
/// common case, and it is the case that has to be cheap: an agent refused
/// eighteen times in a session reads eighteen lines, not eighteen paragraphs.
/// The paragraph is still worth having exactly once, when a reader meets a class
/// for the first time — so it lives in the registry and this is what fetches it.
///
/// # Its payload is a deliberate, stated exception to pointer-only output
///
/// House style §6 and non-negotiable rule 4 say a check emits a count, a
/// `path:line` or a boolean, never the content. This prints a paragraph, and
/// that is inside the rule rather than an exception to it in one respect and an
/// exception in another. Inside: the text is the **config author's own
/// declaration**, the class `config show` exists to echo, never content read out
/// of a subject file. Exception: it is a payload, and carrying it is the whole
/// point — a documentation verb that emitted a pointer to its own documentation
/// would be a redirect with extra steps.
///
/// # Local, deterministic, and never a verdict
///
/// No network, no spawn, no tree walk: the committed registry is resolved and a
/// token is looked up in it. Exit `0` for a token the registry declares, `1` for
/// one it does not or for a registry that will not load, `3` for an internal
/// fault — and never `2`, because this decides nothing about the repository.
///
/// # Errors
///
/// Propagates a config-resolution failure, which is the usage class (exit `1`).
fn run_policy_explain(
    token: &str,
    json: bool,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    // A CONFIG THAT WILL NOT LOAD IS EXACTLY WHEN A CLASS NEEDS EXPLAINING
    // (CLOUD-1313). This used to be `resolve::resolve(..)?`, so `explain` died
    // on the load before it could consult any registry — measured on a repo whose
    // `batten.toml` carries one malformed table:
    //
    //     $ batten policy explain "path write refused"
    //     batten: invalid config ./batten.toml: TOML parse error at line 3
    //
    // `path write refused` is VENDORED. It needs no consumer config, it is what
    // the mediated boundary raises dozens of times a session, and its remedy was
    // unreachable in the one repository state where a reader is most likely to be
    // stuck. The remedy channel went dark precisely when the config broke.
    //
    // So a load failure degrades rather than refuses: the union where a config
    // loads — which is what stops `explain` resolving a token differently from
    // the gate that raised it — and this binary's vendored classes where it does
    // not. What genuinely needs the config still says so below rather than
    // guessing: a `[[rule]]` id and a `[[redirect]]` remedy are the consumer's,
    // and neither is answerable from a config nobody could read.
    let config = resolve::resolve(Path::new("."), overrides).ok();
    let registry = match &config {
        Some(config) => policy::registry_for(&config.verdicts)?,
        None => verdict::vendored(),
    };
    let Some((resolved, retired)) = verdict::resolve(&registry, token) else {
        // A RULE ID RESOLVES HERE TOO (CLOUD-1286), and that is what makes "the
        // token is the pointer to the fix" true rather than aspirational. The
        // emitted line carries a class AND the rule id that fired, and the two
        // answer different halves: the class is Batten's, the row's `reason` is
        // the CONSUMER's remedy — "use `mise run land`", "reach for the
        // structured surface". Taking that prose off the hot path without giving
        // it a lookup would be a refusal naming no remedy, which is the class
        // `crate::verdict`'s own header exists to kill.
        //
        // Tried second rather than first because a class is what a reader most
        // often has, and the two namespaces cannot collide: a class is three
        // lowercase words and a rule id is a kebab-case identifier.
        if let Some(rule) = config
            .as_ref()
            .and_then(|config| config.rules.iter().find(|rule| rule.id == token))
        {
            let facts = config
                .as_ref()
                .map_or(&[][..], |config| config.facts.as_slice());
            return explain_rule(rule, facts, json, out);
        }
        // THE DERIVED PROTECTED GATE HAS NO `[[rule]]` ROW, and its remedy is
        // per PATH CLASS rather than per rule (CLOUD-280): a `[[redirect]]`
        // row's `mutation`, chosen by which glob matched. That remedy left the
        // emitted line with everything else, and it is the one that had nowhere
        // to land — a class hop answers about `path write refused` generically
        // and a rule hop has no row to find. So the gate's own id resolves here,
        // to the table that answers "what do I do instead for THIS path".
        // THE CONSUMER'S OWN TABLES, so this arm needs a config that loaded.
        // Absent one it falls through to the refusal below, which says the class
        // is undeclared HERE rather than pretending an empty redirect table is
        // an answer — an empty "what to do instead" reads as "nothing to do".
        if let (true, Some(config)) = (token == hook::PROTECTED_MUTATION, config.as_ref()) {
            return explain_redirects(&config.redirects, &config.verbs, json, out);
        }
        // Named, and the token is the caller's own argument rather than
        // anything read out of the tree. A list of what IS declared would be the
        // whole registry on stderr; the count plus the verb to run is the
        // pointer-shaped answer.
        return Err(error::UsageError::raise(format!(
            "no `[[verdict]]` row and no `[[rule]]` row declares `{token}`; this registry \
             declares {} class(es) and this config declares {}",
            registry.len(),
            // THREE-VALUED, because "0 rules" and "no config could be read" are
            // different answers and collapsing them would send a reader looking
            // for a missing row when the real fault is the file.
            config.as_ref().map_or_else(
                || "no rules (this config could not be read)".to_owned(),
                |config| format!("{} rule(s)", config.rules.len()),
            ),
        )));
    };
    if json {
        writeln!(out, "{}", explain_json(token, resolved, retired)?)?;
        return Ok(ExitCode::Success);
    }
    writeln!(out, "{} {}", resolved.id, resolved.gloss)?;
    if retired {
        // The token the reader ASKED for was a tombstone. Said outright rather
        // than silently swapped: a reader who greps their own logs for the old
        // token has to learn that it moved, and an answer that just showed the
        // new class would leave them believing the old one is live.
        writeln!(out, "retired  {token} -> {}", resolved.id)?;
    }
    writeln!(out)?;
    writeln!(out, "{}", resolved.class.trim())?;
    writeln!(out)?;
    for route in &resolved.routes {
        let target = match route.precondition.as_deref() {
            Some(precondition) => precondition,
            None => route.target.as_str(),
        };
        writeln!(out, "{}  {}  {target}", route.id, route.kind.as_str())?;
    }
    Ok(ExitCode::Success)
}

/// Resolve a `[[rule]]` id to the remedy its row declares (CLOUD-1286).
///
/// The consumer half of `explain`. A row's `reason` is documented as "what to do
/// instead", so it is the remedy a reader wants after a deny — and since the
/// emitted line stopped carrying it, this is where it went. Same shape as the
/// class half above and the same exception to pointer-only output, for the same
/// stated reason: the text is the config author's own declaration, echoed back,
/// never content read out of a subject file.
/// Resolve the derived protected gate to the table that answers it (CLOUD-1286).
///
/// Both tiers, in the order the boundary applies them: a `[[redirect]]` row's
/// `mutation` speaks for a PATH CLASS and wins, and a `[[verb]]` row's
/// `redirect` is the general remedy for the program. Printing only the first
/// would leave the fallback unreachable, which is the tier this repository's own
/// `rm` and `mv` rows land in.
fn explain_redirects(
    redirects: &[redirect::Redirect],
    verbs: &[verbs::MutatingVerb],
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rule": hook::PROTECTED_MUTATION,
                "redirects": redirects,
                "verbs": verbs,
            }))?
        )?;
        return Ok(ExitCode::Success);
    }
    writeln!(out, "{} protected", hook::PROTECTED_MUTATION)?;
    writeln!(out)?;
    for row in redirects {
        writeln!(out, "{}  {}", row.glob, row.mutation)?;
        // The READ remedy where a class declares one (CLOUD-1258). Printed on
        // its own line rather than folded into the mutation's, because they are
        // answers to two different questions and a reader arriving from a read
        // refusal must not have to pick the right half out of one sentence.
        if let Some(read) = row.read.as_deref() {
            writeln!(out, "{}  read  {read}", row.glob)?;
        }
    }
    for row in verbs {
        if let Some(redirect) = row.redirect.as_deref() {
            writeln!(out, "{}  {redirect}", row.verb)?;
        }
    }
    Ok(ExitCode::Success)
}

/// THE DECLARED COMMANDS ARE PART OF THE ANSWER, not decoration. Where a
/// `receipt` row's checks name agent-sourced facts, the remedy is the exact
/// command whose output will be accepted (CLOUD-776) — byte-identical to what
/// the record is then verified against, which is what closes the loop and what a
/// second wording of it would break. That command left the emitted line with
/// everything else, so it has to arrive here or the loop does not close.
fn explain_rule(
    rule: &rules::Rule,
    facts: &[facts::Declared],
    json: bool,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let commands: Vec<&str> = rule
        .checks
        .iter()
        .flatten()
        .filter_map(|check| facts.iter().find(|fact| &fact.name == check))
        .filter_map(|fact| fact.command.as_deref())
        .collect();
    if json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "rule": rule.id,
                "kind": rule.kind.as_str(),
                "reason": rule.reason,
                "commands": commands,
            }))?
        )?;
        return Ok(ExitCode::Success);
    }
    writeln!(out, "{} {}", rule.id, rule.kind.as_str())?;
    writeln!(out)?;
    match rule.reason.as_deref() {
        Some(reason) => writeln!(out, "{}", reason.trim())?,
        // Stated rather than silent, exactly as `Fix::None` is: a reader cannot
        // tell an absent remedy from a verb that forgot to print one.
        None => writeln!(out, "this row declares no remedy of its own")?,
    }
    if !commands.is_empty() {
        writeln!(out)?;
        for command in commands {
            writeln!(out, "{command}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Dispatch the `policy` subtree.
///
/// Lifted out of [`run`]'s table alongside [`run_override`] and for the same
/// reason: that body is one line per verb, and a three-verb nested match is not
/// one line.
fn run_policy(
    command: PolicyCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        PolicyCommand::Budget { json } => run_budget(json, overrides, out),
        PolicyCommand::Test { json } => run_policy_test(json, overrides, out),
        PolicyCommand::Tools { json } => run_policy_tools(json, overrides, out),
        PolicyCommand::Explain { token, json } => run_policy_explain(&token, json, overrides, out),
        PolicyCommand::Hooks { json } => run_policy_hooks(json, overrides, out),
    }
}

/// Judge this session's hook output against its declared budget (CLOUD-417).
///
/// # The measurement runs whether or not a ceiling is declared
///
/// That split is the row's own acceptance clause made structural: *"the
/// measurement is re-runnable against any transcript, so the 20% figure can be
/// checked rather than believed"*. So an undeclared `[hook_output]` still prints
/// the reading and exits `0` — a repository can read its own number before
/// choosing one, and the number is derived rather than typed into a body.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) when no transcript is configured or the
/// configured one cannot be read: this verb's whole subject is that file, so
/// could-not-look must be an error rather than a vacuous pass over nothing —
/// exactly the shape `budget`'s dead-glob refusal takes one verb up.
fn run_policy_hooks(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let path = transcript::configured_path(config.transcript.as_ref()).ok_or_else(|| {
        UsageError::raise(format!(
            "no [transcript] path in {}; there is no session to measure",
            config::CONFIG_FILE
        ))
    })?;
    let label = path.display().to_string();
    let body = std::fs::read_to_string(&path)
        .map_err(|_| UsageError::raise(format!("{}: {label}", transcript::UNREADABLE_NOTICE)))?;
    let stream = transcript::parse(&body, &label)?;
    let reading = hookcost::measure(&stream);
    let findings = hookcost::judge(&reading, config.hook_output.as_ref());
    if json {
        // Emitted unconditionally, including for a session within budget: JSON
        // that is sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&reading)?)?;
    } else {
        // ONE LINE, always — the self-applying property, and the reason this
        // verb does not print a per-producer breakdown the way `budget` prints
        // per-file rows. A gate about hook volume whose own report grows with
        // what it found would be the defect wearing the sensor's clothes; the
        // producers that actually broke a threshold are named in the findings
        // below, which is where a reader who needs one goes.
        output::line(out, &reading)?;
        // `<subject> <rule>`, the shape every other pointer line here takes,
        // with the transcript line appended where the finding has one — a
        // repeat's pointer IS the first copy, so it is the field a reader
        // acts on. Rendered through `output::lines` rather than through
        // `refusal::render` because these are findings about a measurement
        // rather than a refusal of a call, and there is no route out of one to
        // advertise.
        output::lines(out, &findings)?;
    }
    Ok(ExitCode::verdict(!findings.is_empty()))
}

/// Dispatch the `override` subtree.
///
/// One arm today, and a function rather than an inline match for the reason
/// every other multi-verb noun here has one: [`run`]'s body is a table of one
/// line per verb, and a verb whose arm is a nested destructure stops it being
/// readable as a table.
fn run_override(
    command: OverrideCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        OverrideCommand::Request {
            rule,
            verdict,
            subject,
        } => run_override_request(&rule, &verdict, &subject, overrides, out, err),
        OverrideCommand::Spend {
            admission,
            rule,
            verdict,
            subject,
        } => run_override_spend(&admission, &rule, &verdict, &subject, overrides, out, err),
    }
}

/// `batten override spend` — consume an admission for the situation it names
/// (CLOUD-1051).
///
/// # Why this is a verb and not a flag on the gate
///
/// `check` is declared `read`, and [`perform_requested_sinks`] states the rule
/// that keeps it honest: a read-effect verb that left a record behind would be a
/// verb that changes what it is judging. Spending moves a record from issued to
/// spent, which is a write — so the gate's task calls this AFTER the refusal
/// rather than the gate consuming its own override mid-decision.
///
/// # The situation is re-stated rather than remembered
///
/// The caller passes the rule, the class and the subject again instead of having
/// them read out of the record. Reading them from the record would make every
/// spend self-consistent by construction and the binding decorative: the whole
/// content of an admission is that it is valid for ONE situation, so the
/// situation has to come from the caller and be COMPARED.
///
/// HEAD and the epoch are resolved here for [`run_override_request`]'s reason,
/// inverted: a caller who could choose them could present a stale admission
/// against a moved tree or a changed policy.
///
/// # Exit codes
///
/// `0` spent. `2` refused — every [`admission::Refused`] arm, because a refusal
/// to release is a policy verdict and §7 gives that one code on every verb. `3`
/// when the store itself cannot be read or written, which is an internal fault
/// rather than a statement about the admission.
///
/// # Errors
///
/// Returns an internal error when the store cannot be reached.
fn run_override_spend(
    admission: &str,
    rule: &str,
    token: &str,
    subject: &str,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    // Resolved rather than taken, exactly as `request` resolves them.
    let head = git::head_commit(root)?;
    let (epoch, _) = epoch::describe(root, overrides.config_from.as_deref())?;
    let situation = admission::Situation {
        rule,
        verdict: token,
        subject,
        head: &head,
        epoch: &epoch,
    };
    match admission::consume(root, admission, &situation)? {
        Ok(record) => {
            // The pointer line first and unchanged: the address and the class,
            // which is what a reader needs to find the record.
            writeln!(out, "{} {} spent", record.binding.verdict, admission)?;
            // THEN THE BLOCK, AND THE COMMENT THIS REPLACES HAD RULE 4 BACKWARDS
            // (CLOUD-1278). It read "POINTER, NEVER THE ANSWERS (rule 4) … the
            // reasoning the author typed stays in the store where it was
            // written", and that reflex is what made the whole mechanism a toll
            // with no product. Rule 4 keeps a gate from republishing REPOSITORY
            // CONTENT — a secret it scanned, a subject line somebody typed, a
            // file it read. An articulation is none of those. It is the caller's
            // own words, composed for the express purpose of being read by a
            // reviewer, and `admission.rs`'s header says so outright: an address
            // "authorizes nothing on its own", so a record is "safe to print,
            // log, quote in a commit and leave in a transcript".
            //
            // `refusal.rs` already calls this "rule 4's deliberate inversion".
            // Keeping the answers in a container-scoped store honoured the letter
            // of a rule that was not about them, and cost the design its entire
            // point: nobody could read the reasoning an override had bought, so
            // there was nothing to diagnose after the fact and nothing for a
            // review bot to bound a blast radius with.
            //
            // Printed AFTER the pointer line rather than instead of it, so a
            // caller parsing the first line is unaffected.
            write!(out, "{}", admission::block(&record))?;
            Ok(ExitCode::Success)
        }
        Err(refused) => {
            writeln!(
                err,
                "::error:: admission {admission} is {} for {rule}/{token}",
                refused.as_str()
            )?;
            Ok(ExitCode::Violation)
        }
    }
}

/// `batten override request` — issue an admission for one situation
/// (CLOUD-1051).
///
/// # What the caller supplies and what this resolves
///
/// The caller names the rule, the class and the gate's canonical subject; the
/// other two binding terms — HEAD and the config epoch — are resolved HERE. That
/// asymmetry is the point: an admission whose HEAD the caller could choose would
/// bind nothing, and one whose epoch the caller could choose would survive the
/// policy change that made it unnecessary.
///
/// # The questions, and the two-step this produces
///
/// They are generated from the class's own declared `override.precondition`, so
/// a class that declares no override route cannot be overridden at all — the
/// right default, and the one `verdict::validate` already composes with by
/// refusing a class whose ONLY route is an override.
///
/// Run with nothing on stdin, this PRINTS the questions and exits `1`. That is
/// the "an unanswered question yields no admission" clause and the
/// re-presentation of the declined routes in one step, at the last cheap moment
/// — which is what catches the reader who never received route 1 (CLOUD-1050
/// defect B, measured).
///
/// # It never grades an answer
///
/// Non-negotiable rule 3. The predicate is presence and non-emptiness; anything
/// stronger is a model verdict inside a gate, which would be worse than today's
/// password.
///
/// # Errors
///
/// Returns a [`error::UsageError`] for an unknown class or a class that declares
/// no override route, and an internal error when the store cannot be written.
fn run_override_request(
    rule: &str,
    token: &str,
    subject: &str,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    let config = resolve::resolve(root, overrides)?;
    let registry = policy::registry_for(&config.verdicts)?;
    let Some((resolved, _)) = verdict::resolve(&registry, token) else {
        return Err(error::UsageError::raise(format!(
            "no `[[verdict]]` row declares `{token}`; this registry declares {} class(es)",
            registry.len()
        )));
    };
    let Some(questions) = admission::questions_for(resolved) else {
        // Not a failure of the request — a statement about the class. A class
        // that declares no override route is one this repository decided cannot
        // be overridden, and saying so is more useful than issuing something the
        // gate would then refuse.
        return Err(error::UsageError::raise(format!(
            "{} declares no `override` route, so it cannot be overridden",
            resolved.id
        )));
    };

    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        raw.clear();
    }
    let answers = parse_answers(&raw);
    let missing = admission::unanswered(&questions, &answers);
    if !missing.is_empty() {
        for question in &questions {
            writeln!(err, "{}  {}", question.id, question.prompt)?;
        }
        writeln!(
            err,
            "::error:: {} question(s) unanswered. Answer each as `<id>=<text>` on stdin.",
            missing.len()
        )?;
        return Ok(ExitCode::Usage);
    }

    let head = git::head_commit(root)?;
    // The SAME epoch `config epoch` reports, resolved through the same function,
    // so an admission cannot bind a generation the caller could not look up.
    let (epoch, _) = epoch::describe(root, None)?;
    // `user.email` rather than a name: it is the accountable identity
    // `[attribution]` already decides over, and it is never a model identity
    // (`.claude/rules/commits.md`). An unset one is the empty string rather than
    // a failure — the author is a field of the record, not a precondition of it,
    // and refusing an override because git has no email configured would put a
    // gate in front of the break-glass for a reason unrelated to the situation.
    let author = git::config_value(root, "user.email")
        .ok()
        .flatten()
        .unwrap_or_default();
    let prev = admission::chain_head(root, rule, subject)?;
    let binding = admission::Binding {
        rule: rule.to_owned(),
        verdict: resolved.id.clone(),
        subject: subject.to_owned(),
        head,
        epoch,
        answers,
        prev,
        author,
    };
    let issued = admission::issue(root, binding)?;
    // The admission alone on stdout. It authorizes nothing on its own — the
    // record's existence and state do — which is exactly what makes it safe to
    // print, log, and quote in a commit.
    writeln!(out, "{issued}")?;
    Ok(ExitCode::Success)
}

/// Read `<question-id>=<answer>` lines into an answer map.
///
/// Everything after the FIRST `=` is the answer, so an answer may contain one;
/// a line with no `=` is not an answer and is dropped rather than guessed at.
/// Blank lines are skipped so a caller can lay the block out readably.
fn parse_answers(raw: &str) -> std::collections::BTreeMap<String, String> {
    raw.lines()
        .filter_map(|line| {
            let (id, answer) = line.split_once('=')?;
            let id = id.trim();
            (!id.is_empty()).then(|| (id.to_owned(), answer.trim().to_owned()))
        })
        .collect()
}

/// The `-J` shape of [`run_policy_explain`], byte-stable.
///
/// `token` and `resolved` are both carried, and they differ exactly when the
/// asked-for token was a tombstone — which is the one fact a caller reading this
/// programmatically cannot reconstruct from either alone.
fn explain_json(token: &str, resolved: &verdict::DeclaredVerdict, retired: bool) -> Result<String> {
    let routes: Vec<serde_json::Value> = resolved
        .routes
        .iter()
        .map(|route| {
            serde_json::json!({
                "id": route.id,
                "kind": route.kind.as_str(),
                "target": route.target,
                "precondition": route.precondition,
            })
        })
        .collect();
    Ok(serde_json::to_string(&serde_json::json!({
        "token": token,
        "resolved": resolved.id,
        "retired": retired,
        "gloss": resolved.gloss,
        "class": resolved.class.trim(),
        "routes": routes,
    }))?)
}

// The length is the four report terms rendered in two output shapes, and the
// exit derivation beneath them. Splitting the rendering out would separate the
// terms from the verdict they feed, which is exactly the drift the exit
// expression at the bottom records (CLOUD-857).
#[expect(
    clippy::too_many_lines,
    reason = "the report's terms and the verdict they decide belong in one place; separating them is how a term came to report without deciding"
)]
fn run_policy_test(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let root = Path::new(".");
    let config = resolve::resolve(root, overrides)?;
    let bundles = policy::load(
        root,
        &config.rules,
        policy::Vocabulary {
            patterns: &config.patterns,
            verdicts: &config.verdicts,
            recorders: &config.recorders,
        },
        policy::ModuleChecks::Run,
        overrides.config_from.as_deref(),
    )?;
    // The same walk the tree engine hoists, so a suite's input carries the same
    // `tracked` a real `check` would hand the bundle (CLOUD-845). Resolved once
    // here rather than per row, for the reason `rules::run` gives.
    // §4's "cheap when irrelevant": a config declaring no policy row pays no
    // walk. `tree_files` walks the whole repository, and this verb reported
    // `0 bundle(s)` after paying for it.
    let tracked = if config
        .rules
        .iter()
        .any(|rule| rule.kind == rules::RuleKind::Policy)
    {
        rules::tree_files(root)?
    } else {
        Vec::new()
    };
    // The same shared acquisition a real `check` does, so a suite's input is the
    // one the engine would build — including the one-read-per-path property
    // (CLOUD-850).
    let documents = rules::acquire_declared(&config.rules, root, &tracked)?;

    let mut reports = Vec::new();
    for rule in config
        .rules
        .iter()
        .filter(|rule| rule.kind == rules::RuleKind::Policy)
    {
        let Some(bundle) = bundles.iter().find(|bundle| bundle.id() == rule.id) else {
            // A row whose bundle never loaded. Not a pass: this verb has nothing
            // to decide with, and reporting clean would be a suite that never
            // ran reading as one that found nothing.
            reports.push(SuiteReport::not_run(&rule.id, Vec::new()));
            continue;
        };
        // The same input a tree-scoped row would hand this bundle. A
        // mediated-call row declares no documents, so its tests run against `{}`
        // and supply their own input with `with input as` — OPA and Conftest's
        // own shape, and the reason neither surface needs a fixture key.
        let (input, not_acquired) = suite_input(rule, &documents, &tracked)?;
        if !not_acquired.is_empty() {
            // Pointer-only (rule 4): the PATH and its stated cause, never a byte
            // of the document. The cause is CLOUD-849's — before it, all four
            // ways a declared document can fail to arrive looked identical here.
            let missing = not_acquired
                .into_iter()
                .map(|(path, why)| format!("{path} ({})", why.as_str()))
                .collect();
            reports.push(SuiteReport::not_run(&rule.id, missing));
            continue;
        }
        // THE SCOPE TRAVELS RATHER THAN BEING SNIFFED (CLOUD-857). Only a
        // mediated-call row is handed a command, so only its modules can be
        // asked whether a test ever passed a compound one; `policy.rs` would
        // otherwise have to guess a module's surface from its literals, which is
        // the kind of inference `rules-drift` exists to make unnecessary.
        match policy::test(bundle, &input, rule.scope == rules::RuleScope::MediatedCall)? {
            facts::Look::Is(suite) => reports.push(SuiteReport {
                bundle: rule.id.clone(),
                looked: true,
                missing: Vec::new(),
                passed: suite.passed,
                failed: suite.failed,
                unexercised: suite.unexercised,
                untested_modules: suite.untested_modules,
                bare_only_modules: suite.bare_only_modules,
            }),
            facts::Look::IsNot | facts::Look::CouldNotLook => {
                reports.push(SuiteReport::not_run(&rule.id, Vec::new()));
            }
        }
    }

    if json {
        // Emitted unconditionally, including for a clean run: JSON that is
        // sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&reports)?)?;
    } else {
        for report in &reports {
            for path in &report.missing {
                writeln!(out, "{} {FIXTURE_MISSING} {path}", report.bundle)?;
            }
            if !report.looked && report.missing.is_empty() {
                writeln!(out, "{} {SUITE_NOT_RUN}", report.bundle)?;
            }
            for id in &report.failed {
                writeln!(
                    out,
                    "{} {TEST_FAILED} {} {}",
                    report.bundle, id.module, id.name
                )?;
            }
            for id in &report.unexercised {
                writeln!(out, "{} {PREDICATE_UNEXERCISED} {id}", report.bundle)?;
            }
            for path in &report.untested_modules {
                writeln!(out, "{} {MODULE_UNTESTED} {path}", report.bundle)?;
            }
            for path in &report.bare_only_modules {
                writeln!(out, "{} {MODULE_BARE_ONLY} {path}", report.bundle)?;
            }
        }
        let passed: usize = reports.iter().map(|report| report.passed.len()).sum();
        let failed: usize = reports.iter().map(|report| report.failed.len()).sum();
        writeln!(
            out,
            "policy test: {} bundle(s), {passed} passed, {failed} failed",
            reports.len()
        )?;
    }

    // A suite that could not run is exit `1` — the config class — and it wins
    // over a verdict, because a run that did not happen must never be reported
    // as one that found nothing.
    if reports.iter().any(|report| !report.looked) {
        return Ok(ExitCode::Usage);
    }
    // THE TERMS ARE LISTED ONCE, and this call site is why that matters
    // (CLOUD-857). `Suite::is_violation` states which terms decide, and this
    // expression re-derived the same list — so adding a deciding term to the
    // Suite left the CLI reporting it and exiting 0, which is a finding that
    // decides nothing wearing a gate's output. Measured on the term this row
    // adds, before this line changed.
    //
    // Kept as a local rather than folded into `Suite`, because the report is
    // what survives the loop above; the point is that its predicate is spelled
    // in exactly the same terms as the type's.
    Ok(ExitCode::verdict(reports.iter().any(|report| {
        !report.failed.is_empty()
            || !report.unexercised.is_empty()
            || !report.bare_only_modules.is_empty()
    })))
}

/// Resolve the `[attribution]` table, or say why the gate cannot decide.
///
/// An absent table is exit `1`, never a clean pass: "this repository declares no
/// attribution policy" and "these commits are clean" are different answers, and
/// collapsing them would report green over a gate that never ran.
fn attribution_policy(overrides: &Overrides) -> Result<attribution::Attribution> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    config.attribution.clone().ok_or_else(|| {
        UsageError::raise(format!(
            "no [attribution] in {}; there is no attribution policy to judge by",
            config::CONFIG_FILE
        ))
    })
}

/// The `attribution check -J` document (CLOUD-274, CLOUD-276).
///
/// **One shape, always.** Every key is present on every run, including a clean
/// one and one that named no host — a document whose keys come and go is
/// unparseable, and this is the same rule `decision::Caller` keeps for its own
/// three fields: degrade the VALUE, never the shape.
///
/// Field order is struct order rather than a map's, so the emission is
/// byte-stable (§6).
///
/// Pointer-only (rule 4): `findings` carries a label and a field name,
/// `expects` two vocabulary tokens, and `caller` a harness token plus whatever
/// the declared fidelity allowed — never a line of commit content.
#[derive(serde::Serialize)]
struct AttributionDocument<'a> {
    /// Who made the call, captured at the fidelity the named host declares.
    caller: decision::Caller,
    /// What that host is declared to do to a produced commit.
    expects: Vec<Expectation>,
    /// The verdict half, and the only half that reaches the exit code.
    findings: &'a [attribution::Finding],
}

/// One declared attribution row, as the document renders it.
#[derive(serde::Serialize)]
struct Expectation {
    /// The capability's stable token.
    capability: &'static str,
    /// What this host declares for it: `yes`, `no`, `partial` or `unknown`.
    declares: &'static str,
}

/// Resolve the `[commit]` table, or say why the gate cannot decide.
///
/// An absent table is exit `1`, never a clean pass: "this repository declares no
/// commit convention" and "these subjects are conventional" are different
/// answers, and collapsing them would report green over a gate that never ran.
fn commit_policy(overrides: &Overrides) -> Result<commit::Commit> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    config.commit.clone().ok_or_else(|| {
        UsageError::raise(format!(
            "no [commit] in {}; there is no subject convention to judge by",
            config::CONFIG_FILE
        ))
    })
}

/// Dispatch the `semver` subtree.
///
/// A function rather than an inline match for the reason every other multi-verb
/// noun here has one: [`run`]'s body is a table of one line per verb, and a verb
/// whose arm is a nested destructure stops it being readable as a table.
/// `batten perf pair`: measure this branch against its merge base, or say why not.
///
/// THE EXIT CONTRACT OUTLIVED THE CALLER THAT FORCED IT (CLOUD-1163 unit 10).
/// `mise-tasks/perf-gate.sh` used to run `pair`, redirect it to a file, and
/// distinguish a SKIP from a measurement by looking for `^arm=` — never by a
/// second exit code — because flattening the two would make a shallow clone
/// indistinguishable from a branch that made the hook slower. That program is
/// retired and `Gate` below makes the distinction a variant rather than a
/// reading, but the contract stands unchanged for `pair` INVOKED ALONE, which is
/// still how the noise floor is re-measured: a skip prints its one human line and
/// answers `Success`, and only a could-not-look is non-zero.
fn run_perf(
    command: cli::PerfCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = hook_authority_root();
    match command {
        cli::PerfCommand::Pair { null } => match perf::pair(root, perf::Options { null }) {
            Ok(perf::Outcome::Measured(records)) => {
                for record in records {
                    writeln!(out, "{record}")?;
                }
                Ok(ExitCode::Success)
            }
            Ok(perf::Outcome::Skipped(reason)) => {
                writeln!(out, "{reason}")?;
                Ok(ExitCode::Success)
            }
            // Could-not-look, and it reaches stderr in the `::error::` shape the
            // workflow annotates. A measurement that did not happen is never
            // reported as a verdict about the branch.
            Err(reason) => {
                writeln!(err, "::error:: {reason}")?;
                Ok(ExitCode::Internal)
            }
        },
        cli::PerfCommand::Compare => {
            let mut input = String::new();
            std::io::stdin().read_to_string(&mut input)?;
            report_comparison(
                perf::compare(&input, &exempt_rows(overrides)?, &today()?),
                out,
                err,
            )
        }
        cli::PerfCommand::Gate { null } => {
            match perf::gate(
                root,
                perf::Options { null },
                &exempt_rows(overrides)?,
                &today()?,
            ) {
                // A SKIP IS A PASS. `pair` established that the binary cannot
                // have changed, so there is nothing to compare and nothing to
                // refuse.
                Ok(perf::Gate::Skipped(reason)) => {
                    writeln!(out, "{reason}")?;
                    writeln!(
                        out,
                        "perf-gate: nothing to compare — the binary is unchanged on this branch"
                    )?;
                    Ok(ExitCode::Success)
                }
                Ok(perf::Gate::Judged(comparison)) => report_comparison(Ok(comparison), out, err),
                Err(reason) => {
                    writeln!(err, "::error:: {reason}")?;
                    Ok(ExitCode::Internal)
                }
            }
        }
    }
}

/// The accepted regressions the committed authority declares, or none.
///
/// Absent is an empty table rather than a refusal: a consumer that accepts no
/// regression is the ordinary case, and it must not have to say so.
fn exempt_rows(overrides: &Overrides) -> Result<Vec<config::PerfExempt>> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    Ok(config.perf.map(|perf| perf.exempt).unwrap_or_default())
}

/// Today, as `YYYY-MM-DD`, resolved HERE rather than inside the predicate.
///
/// The clock is a boundary read for the reason `config::deprecation_of` already
/// writes down: a predicate that read the wall clock would answer differently
/// tomorrow for the same commit, which is the one property a gate must not have.
fn today() -> Result<String> {
    Ok(waiver::today()?.text())
}

/// Render a comparison and map it to the exit contract.
///
/// **The codes are BATTEN's, not the retired shell's, and that is a deliberate
/// change rather than a port defect.** `perf-compare.sh` answered 1 for a
/// regression and 2 for could-not-look; here `2` is the policy verdict
/// everywhere and `1`/`3` are the only codes a failure produces, with no per-verb
/// exception. Both callers — `verify` and the `perf` job — test for zero, so no
/// caller can tell the difference; the ledger records it as `changed` rather than
/// carried so a reader is not told the codes survived.
fn report_comparison(
    comparison: Result<perf::Comparison>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let comparison = match comparison {
        Ok(comparison) => comparison,
        Err(reason) => {
            writeln!(err, "::error:: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    // A lapsed exemption is reported whether or not the path then regressed: the
    // row stopped applying, and that is news even on a branch inside the
    // ordinary threshold.
    for line in &comparison.lapsed {
        writeln!(err, "::error:: {line}")?;
    }
    // LOUD ON EVERY RUN, on stderr beside the refusals, because this is the line
    // that stops an accepted regression from becoming invisible.
    for line in &comparison.accepted {
        writeln!(err, "::warning:: {line}")?;
    }
    if comparison.regressed.is_empty() {
        output::line(out, &comparison)?;
        return Ok(ExitCode::Success);
    }
    writeln!(
        err,
        "::error:: {}",
        perf::regression_header(comparison.threshold)
    )?;
    for line in &comparison.regressed {
        writeln!(err, "{line}")?;
    }
    Ok(ExitCode::Violation)
}

/// `batten mutate`: does each declared gate have a mutation its declared suite
/// is proven to catch (CLOUD-418, CLOUD-1267)?
///
/// **The report is the deliverable and the exit code is the verdict**, and the
/// two say different things on purpose. Every finding reaches stdout as a
/// pointer — gate, mutation id, case — because the workflow that runs this cats
/// the file into a step summary, and a run that fails without publishing what it
/// found sends the reader back to re-run a sweep that costs the better part of
/// an hour. The `::error::` summary on stderr carries the count and nothing else.
///
/// Exit follows the one table: `2` where the sweep decided against the tree, `3`
/// where it could not look, and the split is the acceptance rather than a
/// nicety — a gate whose declared suite cannot be resolved or run must never be
/// reported as "every mutation caught".
/// The landing lease's nine arms (CLOUD-1274), ported off `mise-tasks/land-lock.sh`.
///
/// # The exit vocabulary is not uniform across these arms, and that is the design
///
/// `authorises` answers `0` run / `3` stop / `2` could not look, because `1`
/// already means "held by someone else" — which there is a REASON to stop rather
/// than the instruction, so a caller keying on `3` cannot mistake a refusal for an
/// error. Every other arm keeps the ordinary pair, and `2` stays "could not look"
/// throughout.
///
/// # Where the fail-open asymmetry lives
///
/// In `authorises` and nowhere else. A lease that cannot be read stops EVERY job
/// in the fleet, where waving one matrix through costs one matrix; every other
/// refusal here fails closed, because the thing it protects is `main` rather than
/// a runner's budget.
fn run_lease(
    command: cli::LeaseCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    let terms = match lease_terms(root) {
        Ok(terms) => terms,
        // A CLONE WITH NO REMOTE IS AN ANSWER FOR THE READ ARMS, and the type
        // above says why. The five arms that reach `swap` still refuse below,
        // because acquiring a lease that has nowhere to live is not something a
        // missing remote makes safe — the split is by EFFECT, exactly as the
        // read-only allowlist draws it.
        //
        // `status` reports it as its own state — never `unheld`, which would say
        // the lease is free, and never `unknown`, which would say nobody could
        // see — with nothing on stderr, because nothing failed.
        //
        // `authorises` answering `Run` here is the arm's whole contract rather
        // than a convenience: it fails OPEN on everything it cannot read, and
        // stopping the fleet because a clone has no remote is exactly the cost
        // that arm exists never to pay. Reaching it required this branch, because
        // the terms resolve BEFORE the arm does.
        Err(TermsMissing::NoRemote) => match command {
            cli::LeaseCommand::Status { json } => {
                return lease_report(json, "unconfigured", &[], out);
            }
            cli::LeaseCommand::Authorises { .. } => {
                writeln!(
                    out,
                    "lease: no remote is configured, so no lease governs this clone"
                )?;
                return Ok(ExitCode::Success);
            }
            cli::LeaseCommand::Check => {
                writeln!(
                    out,
                    "lease: unconfigured - no remote, so there is no lease to judge"
                )?;
                return Ok(ExitCode::Success);
            }
            // `peek` is silent when no lease names a field, and a clone with no
            // lease at all is the same reading.
            cli::LeaseCommand::Peek { .. } => return Ok(ExitCode::Success),
            // `held` asks whether THIS clone holds it. It does not.
            cli::LeaseCommand::Held => return Ok(ExitCode::Violation),
            cli::LeaseCommand::Acquire { .. }
            | cli::LeaseCommand::Renew
            | cli::LeaseCommand::Hold
            | cli::LeaseCommand::Release
            | cli::LeaseCommand::Reserve { .. } => {
                let name =
                    std::env::var("LAND_LOCK_REMOTE").unwrap_or_else(|_| String::from("origin"));
                writeln!(err, "::error:: lease: no remote named {name} is configured")?;
                return Ok(ExitCode::Internal);
            }
        },
        Err(reason) => {
            let name = std::env::var("LAND_LOCK_REMOTE").unwrap_or_else(|_| String::from("origin"));
            writeln!(err, "::error:: lease: {}", reason.say(&name))?;
            // THE DATA CHANNEL STILL EMITS, and this is the arm where it is
            // easiest to forget: the terms fail BEFORE any arm runs, so a
            // reader that asked for JSON got a decode error rather than an
            // answer. Nine arms have no channel and must not have a document
            // invented for them, which is why this asks rather than emitting
            // unconditionally.
            //
            // `surface.rs`'s `data_channel` is the authority on WHICH arms
            // declare one, never this match — and
            // `every_data_channel_verb_emits_one_pure_json_document` is the
            // sensor that keeps the two together: a second arm gaining `-J`
            // turns it red and points here.
            if let cli::LeaseCommand::Status { json: true } = command {
                lease_report(true, "unknown", &[], out)?;
            }
            return Ok(ExitCode::Internal);
        }
    };
    let now = i64::try_from(now_unix()).unwrap_or(i64::MAX);
    match command {
        // FAIL OPEN, and only here. Both `Err` arms below run rather than stop.
        cli::LeaseCommand::Authorises { branch } => {
            let observed = lease::observe(&terms).ok();
            match lease::authorises(observed.as_ref(), &branch, now) {
                lease::Authority::Run(why) => {
                    writeln!(out, "lease: {why}")?;
                    Ok(ExitCode::Success)
                }
                lease::Authority::Stop(why) => {
                    writeln!(out, "lease: {why}")?;
                    Ok(ExitCode::Violation)
                }
            }
        }
        cli::LeaseCommand::Check => run_lease_check(&terms, now, out, err),
        cli::LeaseCommand::Status { json } => run_lease_status(&terms, json, now, out, err),
        cli::LeaseCommand::Peek { field } => run_lease_peek(&terms, &field, now, out, err),
        cli::LeaseCommand::Held => run_lease_held(root, &terms, now, out, err),
        cli::LeaseCommand::Acquire { branch } => {
            run_lease_acquire(root, &terms, &branch, now, out, err)
        }
        cli::LeaseCommand::Renew => run_lease_renew(root, &terms, now, err),
        cli::LeaseCommand::Hold => run_lease_hold(root, &terms, out, err),
        cli::LeaseCommand::Release => run_lease_release(root, &terms, now, out, err),
        cli::LeaseCommand::Reserve { branch } => run_lease_reserve(&terms, &branch, now, out, err),
    }
}

/// Resolve the lease's terms from this checkout.
///
/// **The remote must resolve to a URL rather than a name.** The transport speaks
/// smart-HTTP over the vendored client, which has no notion of a git remote alias,
/// and a name reaching it would be an unresolvable host rather than a clear
/// refusal here.
/// Why a clone has no lease terms, and the two are not the same answer.
///
/// **A clone with no remote is a FACT about the clone, not a failure to look.**
/// The could-not-look guard exists so an unreadable lease is never reported as a
/// free one; a repository with no remote has no lease ref to misread, so folding
/// it into that guard made `lease status` an error in every clone that has not
/// been pushed anywhere — including the census fixture, where every other
/// data-channel verb answers cleanly.
///
/// The distinction is only ever RELAXED for the reporting arms. The write arms
/// refuse either way, because acquiring a lease that has nowhere to live is not
/// something a missing remote makes safe.
enum TermsMissing {
    /// No remote is configured, so this clone cannot participate in a lease.
    NoRemote,
    /// A remote exists and something about reading it failed. This is the
    /// could-not-look the guard is for.
    Unreadable(String),
}

impl TermsMissing {
    /// The diagnostic, for the arms that report one.
    fn say(&self, name: &str) -> String {
        match self {
            TermsMissing::NoRemote => format!("no remote named {name} is configured"),
            TermsMissing::Unreadable(reason) => reason.clone(),
        }
    }
}

/// `batten land` (CLOUD-1335).
///
/// # The exit codes, which are the one table and not a lap's own dialect
///
/// A conflicted replay is `2`. That is the policy verdict everywhere
/// (non-negotiable rule 5) and it is what a conflict is: the lap may not
/// continue, decided by `rebase-conflict-stops-the-lap` over the record this
/// writes rather than by an arm here. A clone this cannot resolve a remote or a
/// branch for is `3` — could-not-look, never a false `2`, because a lap that
/// could not be attempted has not judged the branch.
///
/// A clean replay and an already-current branch are both `0`, and they are told
/// apart on stdout rather than by a code: `Current` means no sha was minted, so a
/// `verify` receipt keyed to the old head is still good and the caller may skip
/// work — a distinction worth a sentence and not worth a third success code.
///
/// # Pointer-only (rule 4)
///
/// A sha, a count, a path. The conflicted arm names the first path and how many
/// there were, never a hunk and never a conflict marker — which is the whole of
/// what a conflict consists of and exactly what a report must not carry.
fn run_land(
    command: &cli::LandCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = Path::new(".");
    // THE BRANCH IS EVERY ARM'S, so it is resolved once and ahead of the split:
    // the record is keyed by it, the push names it, and the pull request is found
    // by it. A detached HEAD can answer none of those, and that is a statement
    // about the clone rather than about the work.
    let Ok(Some(branch)) = git::current_branch(root) else {
        writeln!(err, "::error:: land: a detached HEAD has no branch to key")?;
        return Ok(ExitCode::Internal);
    };

    // ONE EXHAUSTIVE MATCH, on `run_lease`'s shape rather than on the cascade of
    // `matches!` blocks this replaced. A cascade is a shape a new sub-verb has to
    // EXTEND — read the guards, work out which preamble it needs, insert it in the
    // right place — where a match arm is one a new variant SLOTS into and the
    // compiler names the omission. `fast-forward` is the fifth arm to arrive,
    // which is the point at which the difference stops being taste.
    //
    // THE ORDERING THE CASCADE BOUGHT IS KEPT, and kept by construction rather
    // than by a comment asking the next reader to preserve it: `verify` asks about
    // the working tree and `fast-forward` about a pull request, neither of which
    // is a ref, so a clone with no remote still answers both. Only the three
    // ref-shaped arms resolve a remote, and each resolves it for itself.
    match command {
        cli::LandCommand::Verify => run_land_verify(root, &branch, out, err),
        cli::LandCommand::FastForward => run_land_fast_forward(&branch, out, err),
        cli::LandCommand::Replay { reference } => {
            let Some(url) = land_remote(root, err)? else {
                return Ok(ExitCode::Internal);
            };
            run_land_replay(root, &url, reference, &branch, out)
        }
        cli::LandCommand::Wait { reference } => {
            let Some(url) = land_remote(root, err)? else {
                return Ok(ExitCode::Internal);
            };
            run_land_wait(root, &url, reference, &branch, out, err)
        }
        cli::LandCommand::Push => {
            let Some(url) = land_remote(root, err)? else {
                return Ok(ExitCode::Internal);
            };
            run_land_push(root, &url, &branch, out)
        }
        cli::LandCommand::Lap { reference } => {
            let Some(url) = land_remote(root, err)? else {
                return Ok(ExitCode::Internal);
            };
            run_land_lap(root, &url, reference, &branch, out, err)
        }
    }
}

/// How many laps before the loop gives up, when the caller names none.
///
/// TWO, matching the predecessor. It is a RUNAWAY BACKSTOP rather than a budget:
/// a lap that keeps losing to contention converges, and one losing to a conflict,
/// a failed gate or red CI will lose again — so the useful number is small enough
/// that a broken branch stops rather than grinding.
const LAPS: u32 = 2;

/// Drive the whole lap and lap again on any refusal a rebase would clear.
///
/// # Every bound here is a COUNT, and that is load-bearing
///
/// `$LAND_MAX_LAPS` counts laps. Nothing in this loop consults a clock, and the
/// mechanism refusing one is not this doc comment: `clippy.toml` denies both
/// `std::thread::sleep` and `tokio::time::sleep`, and `tests/sleep_ban.rs` holds
/// each ban's stated reason to a bound whose name resolves. A deadline would
/// reintroduce the VM-reap gap the count exists to close, and would land as a
/// false refusal on a slow bot rather than on a broken branch.
///
/// # Which refusals lap and which stop
///
/// The split is whether a REBASE would clear it, and it is the whole design:
///
/// * **Conflict, or a gate that refused** — stop. Both are decisions a human
///   owns, and lapping would re-run them against the same tree to reach the same
///   answer. This is the one step the loop cannot do for you, and lapping OFTEN
///   is what keeps it small.
/// * **A raced push, a stale base, an unanswered wait, a refused or unreadable
///   fast-forward** — lap. Every one of them means the base moved or the answer
///   is not in yet, and the next lap's rebase is exactly the remedy.
///
/// A refusal is the design working rather than a failure: each lap rebases onto a
/// little more landed work, so conflicts arrive one small resolvable increment at
/// a time. Batching laps removes no refusal and only makes each one bigger, which
/// is the inference CLOUD-238 measured an agent making and optimising toward.
///
/// # Exits
///
/// `0` landed. `2` stopped for a decision — a conflict or a refused gate, which
/// is a verdict about this repository. `3` the laps ran out with no answer, which
/// is not a verdict about anything: the branch may be perfectly landable and the
/// bot merely slow.
fn run_land_lap(
    root: &Path,
    url: &str,
    reference: &str,
    branch: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let laps = std::env::var("LAND_MAX_LAPS")
        .ok()
        .and_then(|declared| declared.parse::<u32>().ok())
        .unwrap_or(LAPS);
    'laps: for lap in 1..=laps {
        writeln!(out, "land: lap {lap} of {laps}")?;
        // THE ORDER IS THE LAP, and every step after `replay` is about a head
        // that descends from the current base. What each ANSWER means is
        // `land::progress`'s — one table, read here rather than re-derived per
        // step, so a reader asking "does this lap or stop" has one place to look
        // and a change to the policy cannot land in four `if`s out of five.
        for step in [
            land::Step::Replay,
            land::Step::Verify,
            land::Step::Push,
            land::Step::Wait,
            land::Step::FastForward,
        ] {
            let code = match step {
                land::Step::Replay => run_land_replay(root, url, reference, branch, out)?,
                land::Step::Verify => run_land_verify(root, branch, out, err)?,
                land::Step::Push => run_land_push(root, url, branch, out)?,
                land::Step::Wait => run_land_wait(root, url, reference, branch, out, err)?,
                land::Step::FastForward => run_land_fast_forward(branch, out, err)?,
            };
            match land::progress(step, code) {
                // THE ONE PLACE THE LAP ASKS A QUESTION OF ITS OWN, and it asks
                // it here because this is the last free moment: everything after
                // `verify` is metered. A base that moved while the gate ran makes
                // the push a matrix spent to learn what one ref read already
                // knows. Fails open — see `land::stale`.
                land::Progress::Proceed if step == land::Step::Verify => {
                    if let Some(moved) = land::stale(root, url, reference) {
                        writeln!(
                            out,
                            "land: lap {lap} — {reference} moved to {moved} while the gate ran; lapping before a matrix is spent"
                        )?;
                        continue 'laps;
                    }
                }
                land::Progress::Proceed => {}
                land::Progress::Landed => {
                    writeln!(out, "land: landed on lap {lap}")?;
                    return Ok(ExitCode::Success);
                }
                land::Progress::Lap => {
                    writeln!(
                        out,
                        "land: lap {lap} — {step:?} says lap; rebasing and retrying"
                    )?;
                    continue 'laps;
                }
                // CARRYING THE STEP'S OWN CODE rather than a code of the loop's.
                // A conflict and a refused gate are both `2`, an unnamed gate is
                // `1`, and an unreadable clone is `3` — the caller reads the same
                // answer it would have got running that step by hand, which is
                // what keeps the loop from becoming a second exit vocabulary.
                land::Progress::Stop => return Ok(code),
            }
        }
    }
    // NOT A VERDICT ABOUT THE BRANCH. Exhausting the count says the loop stopped
    // asking, never that the head is unlandable — so `3`, and the caller runs it
    // again if the laps were lost to contention rather than to a defect.
    writeln!(
        err,
        "::error:: land: {laps} lap(s) bought no landing. A conflict, a failed gate or red CI will lose again — read the lap lines above for how each ended. If every lap lost only to contention, running this again commits up to {laps} more."
    )?;
    Ok(ExitCode::Internal)
}

/// The url of the remote this lap lands against, or `None` having said why.
///
/// `None` rather than an error because every way this fails is a could-not-look
/// about the CLONE — no remotes readable, or none by the configured name — and
/// the caller turns that into the same `Internal` every other unreadable clone
/// produces. Returning the url by value rather than borrowing the remote list
/// keeps the arms above from having to hold it alive across the call.
fn land_remote(root: &Path, err: &mut dyn Write) -> Result<Option<String>> {
    let name = std::env::var("LAND_LOCK_REMOTE").unwrap_or_else(|_| String::from("origin"));
    let Ok(remotes) = git::remotes(root) else {
        writeln!(err, "::error:: land: cannot read this repository's remotes")?;
        return Ok(None);
    };
    let Some((_, url)) = remotes.iter().find(|(configured, _)| *configured == name) else {
        writeln!(
            err,
            "::error:: land: no remote named {name}, so this lap has no base"
        )?;
        return Ok(None);
    };
    Ok(Some(url.clone()))
}

/// `batten land fast-forward` (CLOUD-1338): ask, then read the answer to THAT ask.
///
/// # `$LAND_WORKFLOW` and no default, for `$LAND_VERIFY`'s reason
///
/// The bash lander defaults this to `fast-forward.yml`. That filename is THIS
/// consumer's, and a default compiled in here would be a consumer's vocabulary
/// inside `crates/batten` — non-negotiable rule 1's plainest violation, and the
/// same call `run_land_verify` already makes about the gate's name.
///
/// The failure a default would buy is the quiet one: a repository whose bot lives
/// in a differently-named workflow would read an empty runs list, every lap, and
/// report a silent bot forever. A refusal costs one line of configuration.
///
/// # The three exits, and why the middle one is not an error
///
/// `0` the bot accepted, `2` it refused — the branch is no longer a direct
/// descendant, which is a verdict about this repository and the lap's cue to
/// rebase — and `3` no answer yet, which is the state the loop exists to sit in.
/// A forge that cannot be read is `3` and never a false `2`: a lap that could not
/// look has not been refused.
///
/// `3` is spelled [`ExitCode::Internal`] because the table has four codes and no
/// per-verb exception (non-negotiable rule 5). The variant's name is about where
/// `3` came from historically; what it MEANS here is the same could-not-look
/// [`run_land_wait`] returns for an unanswered race, and the two agree
/// deliberately — a lap reads them through one contract.
/// # It takes no root, and the absence is a statement rather than an oversight
///
/// Every other lap step writes a four-column line to the lap record, which is
/// what gives a `landing-loop` module something to decide over. This one does
/// not, because no predicate reads a fast-forward outcome yet — and a record
/// nothing reads is the dead channel this engine spends its time refusing
/// elsewhere. When a predicate wants one (whether a lap may re-ask after an
/// unknown conclusion is the obvious candidate), the record and the module land
/// together, which is the pairing `.claude/rules/policy-modules.md` requires in
/// both directions.
fn run_land_fast_forward(
    branch: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let workflow = std::env::var("LAND_WORKFLOW").unwrap_or_default();
    if workflow.trim().is_empty() {
        writeln!(
            err,
            "::error:: land fast-forward: $LAND_WORKFLOW names no workflow, and this engine does not know which of this repository's workflows carries the fast-forward verdict"
        )?;
        return Ok(ExitCode::Usage);
    }
    let Some(pr) = fast_forward::open_pull_request(branch) else {
        writeln!(
            err,
            "::error:: land fast-forward: no open pull request for {branch}, so there is nothing to ask"
        )?;
        return Ok(ExitCode::Internal);
    };
    let ask = fast_forward::Ask {
        repo: String::from(pr_watch::REPO_PLACEHOLDER),
        pr,
        workflow,
    };

    // STAMPED BEFORE THE COMMENT, never after, and that ordering is the whole of
    // the anti-livelock property: a run created by an EARLIER lap of this same
    // pull request must fall outside the window. Stamping afterwards would leave
    // a gap in which this lap's own run is created and then excluded by its own
    // fence — a lap that can never read its own answer.
    //
    // `receipt::rfc3339_utc` rather than a second formatter: it is already the
    // crate's one epoch-to-ISO-8601 spelling and its tests pin the instants a
    // hand-rolled one gets wrong (leap years, the 2100 non-leap century).
    let since = receipt::rfc3339_utc(now_unix());

    match fast_forward::ask(&ask)? {
        fast_forward::Asked::Refused(status) => {
            // NEVER ENTER THE POLL. Waiting for the answer to a question nobody
            // received is a hang with a different cause, and the predecessor's
            // was measured: the forge answered a secondary rate limit, nothing
            // read the status, and the lap reported a comment it had not created.
            writeln!(
                err,
                "::error:: land fast-forward: the forge did not create the comment (status {status}); nothing was asked, so there is no answer to wait for"
            )?;
            Ok(ExitCode::Internal)
        }
        fast_forward::Asked::Commented(comment) => {
            writeln!(
                out,
                "land: asked #{} to fast-forward as comment {comment}",
                ask.pr
            )?;
            match fast_forward::answer(&ask, &since, &comment) {
                fast_forward::Answer::Accepted => {
                    writeln!(out, "land: #{} was accepted", ask.pr)?;
                    Ok(ExitCode::Success)
                }
                fast_forward::Answer::Refused => {
                    writeln!(
                        out,
                        "land: #{} was refused; this head is no longer a direct descendant",
                        ask.pr
                    )?;
                    Ok(ExitCode::Violation)
                }
                fast_forward::Answer::Pending => {
                    writeln!(out, "land: #{} has no answer yet", ask.pr)?;
                    Ok(ExitCode::Internal)
                }
                // A CLOSED VOCABULARY REACHES THE READER AS A TOKEN, never as
                // prose and never as "main moved" — that is a fact about a ref,
                // and only the staleness arm may assert it.
                fast_forward::Answer::Unknown(token) => {
                    writeln!(out, "land: #{} ran and decided nothing ({token})", ask.pr)?;
                    Ok(ExitCode::Internal)
                }
            }
        }
    }
}

/// `batten land push`: the branch to its own ref, under receive-pack's CAS.
fn run_land_push(root: &Path, url: &str, branch: &str, out: &mut dyn Write) -> Result<ExitCode> {
    match land::push(root, url, branch)? {
        land::Pushed::Landed(head) => {
            writeln!(out, "land: {branch} on the remote now reads {head}")?;
            Ok(ExitCode::Success)
        }
        // A LOST CAS IS A VERDICT ABOUT THE REPOSITORY, so `2` rather than a
        // failure code: somebody else moved this branch, the lap has an answer,
        // and the answer is to lap again.
        land::Pushed::Raced => {
            writeln!(
                out,
                "land: {branch} moved under this push; the remote refused and this lap is spent"
            )?;
            Ok(ExitCode::Violation)
        }
    }
}

/// `batten land replay`: advance the base and replay this branch onto it.
fn run_land_replay(
    root: &Path,
    url: &str,
    reference: &str,
    branch: &str,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match land::replay(root, url, reference, branch)? {
        land::Replay::Conflicted { commit, paths } => {
            writeln!(
                out,
                "land: replay of {branch} onto {reference} conflicted at {commit} in {} path(s); first is {}",
                paths.len(),
                paths.first().map_or("-", String::as_str)
            )?;
            Ok(ExitCode::Violation)
        }
        land::Replay::Current => {
            writeln!(
                out,
                "land: {branch} already descends from {reference}; nothing replayed"
            )?;
            Ok(ExitCode::Success)
        }
        land::Replay::Replayed { head, commits } => {
            writeln!(
                out,
                "land: replayed {commits} commit(s) of {branch} onto {reference}; head is {head}"
            )?;
            Ok(ExitCode::Success)
        }
    }
}

/// `batten land verify` (CLOUD-1338): the lap's gate, run and recorded.
///
/// # `$LAND_VERIFY` and no default, which is non-negotiable rule 1 as a mechanism
///
/// The bash lander runs `mise run verify`. That name is THIS consumer's, and a
/// default compiled in here would be a consumer's vocabulary inside
/// `crates/batten` — the rule's plainest violation. So the command is read from
/// the environment and an absent one is a `Usage` refusal rather than a guess.
///
/// The failure mode a default would buy is worse than the refusal, which is why
/// this is not merely tidy: a lap in a repository whose gate is spelled
/// differently would run something else, get a `0`, and record the head as
/// verified. A refusal costs one line of configuration; a wrong default costs a
/// receipt that is not true.
///
/// # Whitespace splitting, and its stated bound
///
/// The value is split on whitespace, so a gate whose argv carries a quoted
/// argument with a space in it cannot be spelled here. That bound is real and is
/// accepted rather than papered over with a shell: handing this to `sh -c` would
/// make the engine compose a shell line out of an environment variable, which is
/// exactly the argv-composition `policy/spawn-adapters.rego` records refusing for
/// `prune`'s deletes. A consumer needing that writes a script and names it.
fn run_land_verify(
    root: &Path,
    branch: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let declared = std::env::var("LAND_VERIFY").unwrap_or_default();
    let command: Vec<String> = declared.split_whitespace().map(str::to_owned).collect();
    if command.is_empty() {
        writeln!(
            err,
            "::error:: land verify: $LAND_VERIFY names no command, and this engine does not know what verifying means in this repository"
        )?;
        return Ok(ExitCode::Usage);
    }
    match land::verify(root, branch, &command)? {
        land::Verified::Clean(head) => {
            writeln!(out, "land: {head} passed the configured gate")?;
            Ok(ExitCode::Success)
        }
        // A REFUSAL IS A VERDICT ABOUT THE REPOSITORY, so `2`. The gate's own
        // output already went to the caller's terminal; repeating a pointer to
        // it here would be the payload rule's exact failure.
        land::Verified::Refused(head) => {
            writeln!(out, "land: {head} was refused by the configured gate")?;
            Ok(ExitCode::Violation)
        }
    }
}

/// `batten land wait` (CLOUD-1338): the lap's raced wait, and the record it
/// leaves for a module to decide over.
///
/// # The roster is read from the environment, not from flags
///
/// `pr watch` takes its roster on the command line because a caller may be
/// asking about somebody else's repository. A lap is always asking about THIS
/// one, and the checks that carry a verdict here are already named once, in the
/// consumer's own `$CI_REQUIRED_CHECKS` — which is where the bash lander reads
/// them too. Re-declaring them as flags would put a second spelling of one set
/// on the surface, and the two would drift.
///
/// # Both arms are recorded, winner and loser alike
///
/// [`land::record_wait`] takes both in one call precisely so this cannot write
/// only the winner: a record with one answer and no loser is what a lap that
/// read BOTH sides also produces, and `lap-waits-on-one-answer` would then have
/// nothing to tell them apart.
fn run_land_wait(
    root: &Path,
    remote: &str,
    reference: &str,
    branch: &str,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let Ok(sha) = git::head_commit(root) else {
        writeln!(err, "::error:: land: cannot read this clone's HEAD")?;
        return Ok(ExitCode::Internal);
    };
    let required = std::env::var("CI_REQUIRED_CHECKS").unwrap_or_default();
    let roster = checks_green::Roster {
        required: roster_field(Some(&required)),
        absent_ok: roster_field(std::env::var("CI_ABSENT_OK").ok().as_deref()),
        answered: roster_field(Some(
            &std::env::var("CI_ANSWERED_CONCLUSIONS")
                .unwrap_or_else(|_| String::from("success,failure,timed_out,action_required")),
        )),
        fanin: std::env::var("CI_FANIN_CHECK")
            .ok()
            .filter(|n| !n.is_empty()),
    };
    // BEFORE THE LOOP, exactly as `pr_watch::watch` does it: a roster that can
    // decide nothing is a statement about the invocation, and one polled forever
    // would be a hang whose cause is a typo.
    if let Err(problem) = checks_green::decide(&[], &roster) {
        writeln!(err, "::error:: land wait: {problem}")?;
        return Ok(ExitCode::Usage);
    }

    // The base as this clone last saw it. The wait is asking whether the REMOTE
    // has moved past it, so the comparison needs the local reading rather than a
    // freshly fetched one — a base refreshed first would compare a value to
    // itself and never report stale.
    let tracking = format!(
        "refs/remotes/origin/{}",
        reference.rsplit('/').next().unwrap_or(reference)
    );
    let base = git::resolve_ref(root, &tracking)
        .ok()
        .flatten()
        .unwrap_or_default();

    let config = pr_watch::Config {
        sha: sha.clone(),
        repo: std::env::var("GH_REPO").unwrap_or_else(|_| pr_watch::REPO_PLACEHOLDER.to_owned()),
        interval: 1,
        progress: None,
    };
    // A COUNT, never a deadline (CLOUD-1177). The default is generous because
    // the cost of too many asks is a few conditional requests the forge answers
    // `304`, and the cost of too few is a lap that reports no answer while one
    // was moments away.
    let asks = std::env::var("LAND_ANSWER_MAX_UNKNOWNS")
        .ok()
        .and_then(|raw| raw.parse::<u32>().ok())
        .filter(|asks| *asks > 0)
        .unwrap_or(3600);

    let waited = land::wait(&config, &roster, remote, reference, &base, asks, out)?;
    let (answers, code) = match &waited {
        land::Waited::Green { verdict } => (
            land::answers(&sha, Some(verdict.as_str()), None),
            ExitCode::Success,
        ),
        land::Waited::Stale { base } => (
            land::answers(&sha, None, Some(base.as_str())),
            ExitCode::Violation,
        ),
        land::Waited::Unanswered => (land::answers(&sha, None, None), ExitCode::Internal),
    };
    land::record_wait(root, branch, &answers)?;

    match &waited {
        land::Waited::Green { .. } => {
            writeln!(out, "land: {sha} is green; the loser was voided unread")?;
        }
        land::Waited::Stale { base } => {
            writeln!(
                out,
                "land: {reference} moved to {base} under {sha}; this lap's run is already waste"
            )?;
        }
        land::Waited::Unanswered => {
            writeln!(out, "land: no answer yet on {sha} after {asks} ask(s)")?;
        }
    }
    Ok(code)
}

fn lease_terms(root: &Path) -> std::result::Result<lease::Terms, TermsMissing> {
    let name = std::env::var("LAND_LOCK_REMOTE").unwrap_or_else(|_| String::from("origin"));
    let remotes = git::remotes(root)
        .map_err(|err| TermsMissing::Unreadable(format!("cannot read this repository: {err}")))?;
    let url = remotes
        .iter()
        .find(|(configured, _)| *configured == name)
        .map(|(_, url)| url.clone())
        .ok_or(TermsMissing::NoRemote)?;
    let mut terms = lease::Terms {
        remote: url,
        ..lease::Terms::default()
    };
    // Overridable so a suite can drive the bounds without waiting out a real TTL.
    // Each falls back to the shipped default rather than to zero: a TTL of zero
    // is a lease that has already lapsed, which would report as a fleet with no
    // lease at all rather than as a misconfiguration.
    if let Some(ttl) = env_secs("LAND_LOCK_TTL") {
        terms.ttl = ttl;
    }
    if let Some(beat) = env_secs("LAND_LOCK_HEARTBEAT") {
        terms.beat = beat;
    }
    if let Ok(reference) = std::env::var("LAND_LOCK_BRANCH") {
        terms.reference = format!("refs/heads/{reference}");
    }
    Ok(terms)
}

/// A positive whole number of seconds from the environment, or `None`.
///
/// **Zero and negative are `None`**, not values: every bound here is a duration,
/// and a zero TTL or beat would turn a lease into a spin rather than into a
/// tighter test.
fn env_secs(name: &str) -> Option<i64> {
    std::env::var(name)
        .ok()?
        .parse::<i64>()
        .ok()
        .filter(|seconds| *seconds > 0)
}

/// How many beats a holder may stop progressing before its lease is disbelieved.
///
/// Neither this nor the TTL bounds how long a landing may TAKE — both reset on
/// every advance, so an arbitrarily long landing that keeps producing state
/// changes never reaches either. They bound how long we keep believing a holder
/// that has stopped producing evidence: the TTL notices one that stopped BEATING,
/// this notices one that stopped LANDING.
///
/// 60 beats is 30 minutes against a measured floor of ~45 beats — the longest gap
/// between consecutive check-run completions over the six most recently merged
/// PRs when it was set. Deliberately generous: this exists to catch NEVER, not
/// slow, and the cost of catching slow is a landing killed for being healthy.
fn lease_stall_beats() -> i64 {
    env_secs("LAND_LOCK_STALL_BEATS").unwrap_or(60)
}

/// `lease check`: the lease ref is free, or a live and well-formed hold.
///
/// **Reported, never repaired.** Overwriting a lease this cannot understand is how
/// a well-meant fix races a real holder, so both refusals name what is wrong and
/// leave the decision to a human.
fn run_lease_check(
    terms: &lease::Terms,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    match lease::health(&observed, terms, now) {
        lease::Health::Free(why) | lease::Health::Held(why) => {
            writeln!(out, "lease: {why}")?;
            Ok(ExitCode::Success)
        }
        lease::Health::Wedged(why) => {
            writeln!(
                err,
                "::error:: lease: WEDGED — {why}. Landing is blocked until it expires."
            )?;
            Ok(ExitCode::Violation)
        }
        lease::Health::Garbage(why) => {
            writeln!(err, "::error:: lease: GARBAGE — {why}.")?;
            Ok(ExitCode::Violation)
        }
    }
}

/// `lease status`, which is prose for a human and `-J` for everything else.
fn run_lease_status(
    terms: &lease::Terms,
    json: bool,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            // COULD NOT LOOK IS NOT UNHELD. Reporting it as an unheld lease is
            // the misread that lets two sessions land at once, so this arm is an
            // error where `authorises` runs.
            writeln!(err, "::error:: lease: {reason}")?;
            // AND THE DOCUMENT IS EMITTED ANYWAY, which is not a softening of the
            // line above: `unknown` is a state a reader must be able to
            // distinguish from `unheld`, and a data channel that goes SILENT on
            // this path is unparseable rather than empty — the reader gets a
            // decode error where it asked a question. The exit code carries the
            // verdict; the document carries the answer. `reason` stays on stderr
            // and out of the document, because it is a diagnostic string and the
            // document's fields are tokens.
            lease_report(json, "unknown", &[], out)?;
            return Ok(ExitCode::Internal);
        }
    };
    let body = match &observed {
        lease::Observed::Held { body, .. } => body,
        lease::Observed::Absent => return lease_report(json, "unheld", &[], out),
        // Reported as what it is rather than as a hold. Every DECISION still
        // treats it as held; this is the one place the two can be told apart,
        // which is the whole reason it is a state and not a default body.
        lease::Observed::Garbage { .. } => return lease_report(json, "garbage", &[], out),
    };
    // Checked BEFORE expiry, because a tombstone satisfies both: its expiry is the
    // sentinel, so `now >= 0` is trivially true and the expired arm would render a
    // wall-clock epoch as a duration — observed live, three times, in the
    // predecessor.
    if body.released() {
        return lease_report(json, "released", &[("holder", body.holder.clone())], out);
    }
    if body.expired(now) {
        return lease_report(
            json,
            "unheld",
            &[
                ("holder", body.holder.clone()),
                ("free_for", (now - body.expires).to_string()),
            ],
            out,
        );
    }
    let mut fields = vec![
        ("holder", body.holder.clone()),
        ("branch", body.branch.clone()),
        ("left", (body.expires - now).to_string()),
    ];
    if !body.next.is_empty() {
        fields.push(("next", body.next.clone()));
    }
    // HELD AND ADVANCING IS NOT HELD AND STALLED, and rendering them identically
    // is how a wedged fleet looked healthy for as long as anyone cared to watch.
    //
    // Read from the TOKEN, never from the sighting file: the sighting file is the
    // corroboration a steal acts on, so a reader touching it would move the
    // instant a rival's steal becomes due — and would report nothing on a first
    // call anyway. This is the holder's clock, which is exactly why no PREDICATE
    // may use it; the worst a skewed reading does here is print a number a human
    // squints at.
    if let Some(advance) = body
        .progress
        .split('.')
        .next()
        .and_then(|first| first.parse::<i64>().ok())
        .filter(|advance| *advance > 0)
    {
        let stalled = now - advance;
        if stalled >= lease_stall_beats() * terms.beat {
            fields.push(("stalled", stalled.to_string()));
        }
    }
    lease_report(json, "held", &fields, out)
}

/// One status line, in either channel, from one set of fields.
///
/// Pointer-only in both: a holder id, a ref name and counts of seconds. No lease
/// body reaches either rendering, which is where non-negotiable rule 4 is decided
/// rather than at each call site.
fn lease_report(
    json: bool,
    state: &str,
    fields: &[(&str, String)],
    out: &mut dyn Write,
) -> Result<ExitCode> {
    if json {
        let mut document = serde_json::Map::new();
        document.insert(
            String::from("state"),
            serde_json::Value::String(state.to_owned()),
        );
        for (key, value) in fields {
            document.insert((*key).to_owned(), serde_json::Value::String(value.clone()));
        }
        writeln!(
            out,
            "{}",
            serde_json::to_string(&serde_json::Value::Object(document))?
        )?;
    } else {
        use std::fmt::Write as _;
        let mut rendered = String::new();
        for (key, value) in fields {
            let _ = write!(rendered, " {key}={value}");
        }
        writeln!(out, "lease: {state}{rendered}")?;
    }
    Ok(ExitCode::Success)
}

/// `lease peek`: one advisory field, on stdout, for a caller that means to act.
///
/// Silent and `0` when the lease is absent, released or expired. "No lease names a
/// head" is a legitimate reading a waiter handles by staying on trunk, not an
/// error it should report — and `2` stays reserved for could-not-look.
fn run_lease_peek(
    terms: &lease::Terms,
    field: &str,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let lease::Observed::Held { body, .. } = &observed else {
        return Ok(ExitCode::Success);
    };
    if body.released() || body.expired(now) {
        return Ok(ExitCode::Success);
    }
    match field {
        "branch" => writeln!(out, "{}", body.branch)?,
        "head" => writeln!(out, "{}", body.head)?,
        "next" => writeln!(out, "{}", body.next)?,
        // A CLOSED SET, and an unknown name is a usage error rather than an empty
        // line: the whole value of this verb over the status prose is that a
        // caller can act on the answer, and a silently empty one reads as an
        // unset field.
        other => {
            writeln!(
                err,
                "::error:: lease: {other} is not an advisory field; expected branch, head or next"
            )?;
            return Ok(ExitCode::Usage);
        }
    }
    Ok(ExitCode::Success)
}

/// `lease held`: the pre-comment fence, and the cheap stand-in for a fencing token.
///
/// **It demands MARGIN, not merely a lease that has not expired.** "Not expired"
/// is a fact about the instant of the check, and the caller then goes on to do
/// something — post a comment, wait for a bot — so a lease with one second left
/// passes this and is gone before the action it authorised takes effect. That is
/// the same time-of-check/time-of-use gap the fence exists to close, moved a few
/// lines later.
///
/// One beat is the right margin because it is the interval at which the holder
/// proves it is alive: with a beat left, either the heartbeat renews and the lease
/// keeps rolling, or it does not and this check would have failed anyway.
fn run_lease_held(
    root: &Path,
    terms: &lease::Terms,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (local, holder) = match lease_identity(root) {
        Ok(pair) => pair,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let _ = local;
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let lease::Observed::Held { body, .. } = &observed else {
        return Ok(ExitCode::Violation);
    };
    if body.holder != holder {
        return Ok(ExitCode::Violation);
    }
    if body.expires - now < terms.beat {
        writeln!(
            out,
            "lease: under {}s left — too little to act on",
            terms.beat
        )?;
        return Ok(ExitCode::Violation);
    }
    Ok(ExitCode::Success)
}

/// This clone's bookkeeping directory and its holder id.
fn lease_identity(root: &Path) -> std::result::Result<(lease::Local, String), String> {
    let git_dir =
        git::git_dir(root).map_err(|err| format!("cannot read this repository: {err}"))?;
    let local = lease::Local::under(&git_dir);
    let holder = local
        .holder()
        .map_err(|err| format!("cannot mint a holder id: {err}"))?;
    Ok((local, holder))
}

/// `lease acquire`: one observation, one decision, one compare-and-swap.
///
/// **There is no wait loop here, and that is a deliberate narrowing of the
/// predecessor.** The bash verb blocked with a jittered exponential backoff, which
/// belongs to the LAP rather than to the lease: a caller that already laps —
/// fetch, rebase, verify, wait — re-observes on its own schedule and does not need
/// a second one nested inside it. What is conserved is the decision, which is the
/// part a rival can get wrong; what is dropped is a sleep, which is the part the
/// caller owns.
fn run_lease_acquire(
    root: &Path,
    terms: &lease::Terms,
    branch: &str,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (local, holder) = match lease_identity(root) {
        Ok(pair) => pair,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    // RECORDED ON EVERY OBSERVATION, not only once the lease looks interesting.
    // The corroboration clock starts at the FIRST sighting of a value; starting it
    // only after expiry meant it started once the backoff had already grown, and
    // measured 19s from expiry to steal against a promise of one extra beat.
    let (held_for, progress_for) = match &observed {
        lease::Observed::Held { sha, body } => (
            local.held_for("seen", sha, now),
            if body.progress.is_empty() {
                0
            } else {
                local.held_for("seen-progress", &body.progress, now)
            },
        ),
        // A ref that is not a lease has no sha-of-a-lease to corroborate and no
        // token to compare, so both clocks read zero — which is what keeps it in
        // `Turn::Wait` rather than letting a long watch make it stealable.
        lease::Observed::Absent | lease::Observed::Garbage { .. } => (0, 0),
    };
    let head = git::head_commit(root).unwrap_or_default();
    match lease::turn(
        terms,
        &observed,
        &holder,
        held_for,
        progress_for,
        lease_stall_beats(),
        now,
    ) {
        lease::Turn::Mine => {
            writeln!(out, "lease: already held by this clone")?;
            Ok(ExitCode::Success)
        }
        lease::Turn::Wait => {
            let lease::Observed::Held { body, .. } = &observed else {
                // Unreachable: `Absent` is always a `Take`. Reported rather than
                // unwrapped, because a `Wait` over an absent lease would mean the
                // decision table had changed underneath this arm.
                writeln!(
                    err,
                    "::error:: lease: no lease is held, yet the turn was not taken"
                )?;
                return Ok(ExitCode::Internal);
            };
            writeln!(out, "lease: held by {}", body.holder)?;
            Ok(ExitCode::Violation)
        }
        lease::Turn::Take(why) => {
            let body = lease::claim(terms, &holder, branch, &head, now);
            match lease::cas(terms, &observed, &body, now) {
                Ok(lease::Outcome::Applied) => {
                    lease_receipt(root, branch, now + terms.ttl);
                    writeln!(out, "lease: {why}")?;
                    Ok(ExitCode::Success)
                }
                // LOST THE CAS: somebody claimed the same free state first. An
                // ordinary outcome, and the caller's next lap re-reads and
                // re-decides — no retry here, because an immediate one is the
                // tight spin that turns a contended lease into a busy loop.
                Ok(lease::Outcome::Rejected { .. }) => {
                    writeln!(out, "lease: lost the race for it")?;
                    Ok(ExitCode::Violation)
                }
                Err(reason) => {
                    writeln!(err, "::error:: lease: {reason}")?;
                    Ok(ExitCode::Internal)
                }
            }
        }
    }
}

/// `lease renew`: extend this clone's lease by one term.
fn run_lease_renew(
    root: &Path,
    terms: &lease::Terms,
    now: i64,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (_, holder) = match lease_identity(root) {
        Ok(pair) => pair,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let lease::Observed::Held { body, .. } = &observed else {
        return Ok(ExitCode::Violation);
    };
    if body.holder != holder {
        return Ok(ExitCode::Violation);
    }
    // `None`: this arm is a one-shot with no holder process to read progress
    // from, so it carries the token it found rather than erasing it. A renew that
    // cleared it would make the lease unstealable-forever to every rival.
    let renewed = lease::renewal(terms, body, None, now);
    match lease::cas(terms, &observed, &renewed, now) {
        Ok(lease::Outcome::Applied) => {
            lease_receipt(root, &body.branch, now + terms.ttl);
            Ok(ExitCode::Success)
        }
        Ok(lease::Outcome::Rejected { .. }) => Ok(ExitCode::Violation),
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            Ok(ExitCode::Internal)
        }
    }
}

/// `lease hold`: renew every beat until the lease is lost or the hold ends.
///
/// **A FAILED PUSH IS NOT A LOST LEASE**, and treating it as one was a real
/// fragility in the predecessor: a swap returns non-zero both when the lease
/// genuinely changed hands AND when the push simply did not go through — a dropped
/// connection, a proxy hiccup, a rate limit. Exiting on the second hands the lease
/// away over a blip, and the whole reason the TTL is three beats wide is to survive
/// exactly that. So two consecutive failures are tolerated and a third is not,
/// because past that the remaining TTL is about to run out anyway and continuing
/// to believe we hold it is the one thing this must never do.
fn run_lease_hold(
    root: &Path,
    terms: &lease::Terms,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (_, holder) = match lease_identity(root) {
        Ok(pair) => pair,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let git_dir = git::git_dir(root).unwrap_or_else(|_| root.join(".git"));
    // The land this heartbeat serves, when the caller named one. Unset is "no
    // holder declared", which keeps the behaviour of every caller that is not a
    // landing loop.
    let served = std::env::var("LAND_LOCK_HOLDER_PID")
        .ok()
        .and_then(|pid| pid.parse::<u32>().ok());
    let marker =
        std::env::var("LAND_LOCK_HOLDER_MARKER").unwrap_or_else(|_| String::from("batten land"));
    let mut misses = 0_u32;
    loop {
        // The interval is the lease's own `beat`, and the loop's exit condition is
        // the lease ceasing to be this clone's — or `misses` reaching three, which
        // is the point past which the remaining TTL runs out anyway. Not a timer:
        // there is nothing here a wall clock is standing in for.
        #[expect(
            clippy::disallowed_methods,
            reason = "the heartbeat's interval is the lease's own `beat`; the loop exits when the lease stops being this clone's, or when `misses` reaches three"
        )]
        std::thread::sleep(std::time::Duration::from_secs(
            u64::try_from(terms.beat).unwrap_or(30),
        ));
        let now = i64::try_from(now_unix()).unwrap_or(i64::MAX);
        // BEFORE ANYTHING ELSE EACH BEAT: a heartbeat whose land is gone must not
        // renew a lease for nobody. A kill, an OOM, and an un-reaped task stop all
        // skip the land's own trap, and an orphan that keeps renewing blocks every
        // rival while the lease reads as a healthy hold. Release FIRST, then exit,
        // so the lease frees now rather than after a TTL nobody is refreshing.
        if let Some(pid) = served
            && !lease::holder_alive(pid, &marker)
        {
            writeln!(
                out,
                "lease: the land holding this lease (pid {pid}) is gone; releasing rather than \
                 renewing for nobody"
            )?;
            lease_hand_back(root, terms, &holder, now);
            return Ok(ExitCode::Violation);
        }
        // The complementary case, and the one liveness cannot see: the land is
        // alive, its trap would fire perfectly well, and it has stopped landing.
        // Read the stamps and PUBLISH them, so this beat's mint carries what a
        // rival needs to reach the same conclusion independently.
        let progress = served.and_then(|pid| lease::progress_of(&git_dir, pid));
        if let lease::Bail::Stop(why) = lease::bail(
            progress,
            terms,
            lease_stall_beats(),
            env_secs("LAND_LOCK_HANG_BEATS").unwrap_or(3),
            now,
        ) {
            // RELEASE FIRST, SIGNAL SECOND. The release is the half that frees the
            // fleet and it always lands; the signal's promptness depends on what
            // the land is blocked in. Ordering them the other way would make a
            // fleet-wide unwedge wait on a signal that might be pending.
            writeln!(
                out,
                "lease: the land holding this lease {why}; releasing and stopping it rather than \
                 holding the fleet"
            )?;
            lease_hand_back(root, terms, &holder, now);
            lease_bail_reason(&git_dir, &why);
            // Re-corroborated immediately before the signal, never inferred from
            // the probe at the top of this beat: pids recycle inside twenty
            // minutes on this container, and the stall bound is longer than that.
            if let Some(pid) = served
                && lease::holder_alive(pid, &marker)
            {
                lease::stop(pid);
            }
            return Ok(ExitCode::Violation);
        }
        let Ok(observed) = lease::observe(terms) else {
            misses += 1;
            if misses >= 3 {
                writeln!(
                    out,
                    "lease: could not renew for {misses} beats; letting it lapse rather than \
                     assuming it"
                )?;
                return Ok(ExitCode::Violation);
            }
            continue;
        };
        let lease::Observed::Held { body, .. } = &observed else {
            writeln!(out, "lease: the lease is gone")?;
            return Ok(ExitCode::Violation);
        };
        if body.holder != holder {
            // UNAMBIGUOUS: somebody else's id is on it. No retry can undo that,
            // and pretending otherwise is how two sessions both comment.
            writeln!(out, "lease: lost to {}", body.holder)?;
            return Ok(ExitCode::Violation);
        }
        // PUBLISHED rather than carried, here and only here: this is the one
        // caller that can see the land's own stamps, so it is the one that may
        // replace the token. Every other path carries what it found, because
        // erasing a token it cannot compute would make the lease look
        // unstealable-forever to every rival.
        let token = progress.map(lease::Progress::token);
        let renewed = lease::renewal(terms, body, token.as_deref(), now);
        if let Ok(lease::Outcome::Applied) = lease::cas(terms, &observed, &renewed, now) {
            lease_receipt(root, &body.branch, now + terms.ttl);
            misses = 0;
        } else {
            // A REJECTED SWAP AND A FAILED PUSH ARE ONE ARM HERE, deliberately.
            // The lease being demonstrably somebody else's is decided above, from
            // the holder id, where it is unambiguous; anything that reaches here
            // is a swap that did not land, and a blip is what the three-beat TTL
            // exists to survive.
            misses += 1;
            if misses >= 3 {
                writeln!(
                    out,
                    "lease: could not renew for {misses} beats; letting it lapse rather than \
                     assuming it"
                )?;
                return Ok(ExitCode::Violation);
            }
        }
    }
}

/// Tombstone the lease if this clone still holds it, ignoring every failure.
///
/// **Never fatal, in either direction.** This runs on the paths that are already
/// ending; a clone that cannot reach the remote here has a problem, but the caller
/// is stopping anyway and reporting it would replace the reason it is stopping.
fn lease_hand_back(root: &Path, terms: &lease::Terms, holder: &str, now: i64) {
    let Ok(observed) = lease::observe(terms) else {
        return;
    };
    let lease::Observed::Held { body, .. } = &observed else {
        return;
    };
    if body.holder != holder {
        return;
    }
    if lease::cas(terms, &observed, &lease::tombstone(body), now).is_ok() {
        lease_receipt_clear(root, &body.branch);
    }
}

/// Leave the reason where the agent will look.
///
/// **A landing that stops without saying why reaches its agent as "verify and CI
/// disagree", and the remedy it then reaches for is wrong.** The file is the
/// landing loop's to print and remove; this only writes it, and swallows every
/// failure because a reason that cannot be written must not become a second
/// failure on top of the first.
fn lease_bail_reason(git_dir: &Path, why: &str) {
    let dir = git_dir.join("batten-land-lock");
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(
            dir.join("bail-reason"),
            format!(
                "the landing {why}, so its lease was released and it was stopped. Nothing is \
                 wrong with the branch: look at what its last phase was waiting for, fix that, \
                 and land again.\n"
            ),
        );
    }
}

/// `lease release`: a tombstone, never a delete.
///
/// Releasing a lease this clone does not hold is NOT an error: the trap that calls
/// this fires on every exit path, including ones that never acquired, and exiting
/// non-zero there would turn an orderly cleanup into a reported failure.
fn run_lease_release(
    root: &Path,
    terms: &lease::Terms,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (_, holder) = match lease_identity(root) {
        Ok(pair) => pair,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let lease::Observed::Held { body, .. } = &observed else {
        return Ok(ExitCode::Success);
    };
    if body.holder != holder {
        return Ok(ExitCode::Success);
    }
    // Already handed over: re-tombstoning would mint a second release of the same
    // lease and report an epoch-scale age for it. A release is idempotent in
    // effect, so it must be idempotent in what it says too.
    if body.released() {
        writeln!(out, "lease: already released")?;
        return Ok(ExitCode::Success);
    }
    let dead = lease::tombstone(body);
    match lease::cas(terms, &observed, &dead, now) {
        Ok(lease::Outcome::Applied) => {
            // The receipt GOES rather than ageing out: a release is a declaration
            // that this clone no longer holds it, and leaving one would let the
            // offline reader honour a lease its holder had already handed on.
            lease_receipt_clear(root, &body.branch);
            writeln!(out, "lease: released")?;
            Ok(ExitCode::Success)
        }
        Ok(lease::Outcome::Rejected { .. }) => {
            writeln!(
                out,
                "lease: could not release; it expires in {}s",
                body.expires - now
            )?;
            Ok(ExitCode::Success)
        }
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            Ok(ExitCode::Internal)
        }
    }
}

/// `lease reserve`: take the one slot behind the current holder.
fn run_lease_reserve(
    terms: &lease::Terms,
    branch: &str,
    now: i64,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let observed = match lease::observe(terms) {
        Ok(observed) => observed,
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            return Ok(ExitCode::Internal);
        }
    };
    let held = match &observed {
        lease::Observed::Held { body, .. } if !body.released() && !body.expired(now) => body,
        // Nothing to reserve behind, or a ref that is not a lease. Neither is an
        // error: a free lease means the caller should be ACQUIRING, and a ref
        // nobody can read is the health gate's finding rather than this one's.
        _ => {
            writeln!(out, "lease: no lease is held; acquire rather than reserve")?;
            return Ok(ExitCode::Violation);
        }
    };
    // Reserving behind yourself would authorise your own branch twice and admit
    // nobody, which is worse than doing nothing: it consumes the one slot.
    if held.branch == branch {
        writeln!(out, "lease: {branch} already holds it; nothing to reserve")?;
        return Ok(ExitCode::Violation);
    }
    if !held.next.is_empty() {
        // Idempotent for the branch that already holds the slot, so a waiter
        // re-reserving each lap is a read rather than a churn of the ref.
        if held.next == branch {
            writeln!(out, "lease: {branch} is already the admitted successor")?;
            return Ok(ExitCode::Success);
        }
        writeln!(
            out,
            "lease: {} is already the admitted successor, not {branch}",
            held.next
        )?;
        return Ok(ExitCode::Violation);
    }
    let reserved = lease::reservation(held, branch);
    match lease::cas(terms, &observed, &reserved, now) {
        Ok(lease::Outcome::Applied) => {
            writeln!(
                out,
                "lease: {branch} admitted as the successor behind {}",
                held.branch
            )?;
            Ok(ExitCode::Success)
        }
        // The holder's heartbeat re-minted, or another waiter took the slot first.
        // Either way an ordinary loss, and the caller's next lap re-decides.
        Ok(lease::Outcome::Rejected { .. }) => {
            writeln!(out, "lease: could not reserve; the lease moved")?;
            Ok(ExitCode::Violation)
        }
        Err(reason) => {
            writeln!(err, "::error:: lease: {reason}")?;
            Ok(ExitCode::Internal)
        }
    }
}

/// The offline half a `PreToolUse` guard reads: the instant this clone's lease
/// expires, refreshed by every renewal.
///
/// **Keyed by BRANCH, and slashes are flattened.** Every branch here carries one,
/// and a raw name makes the receipt a path through a directory that does not
/// exist — the write fails, no receipt is left, and the guard then refuses every
/// ready while looking exactly like a mechanism that is working. The predecessor's
/// suites missed it because a scratch repository's default branch is the one shape
/// with no slash in it.
///
/// Never fatal, in either direction. The lease is taken the moment the swap
/// returns; a clone that cannot write to its own `.git` has a problem, but it is
/// not this one, and failing here would report a held lease as unheld.
fn lease_receipt(root: &Path, branch: &str, expires: i64) {
    if let Some(path) = lease_receipt_path(root, branch) {
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let _ = std::fs::write(path, format!("{expires}\n"));
    }
}

/// Remove the receipt a release invalidates. See [`lease_receipt`].
fn lease_receipt_clear(root: &Path, branch: &str) {
    if let Some(path) = lease_receipt_path(root, branch) {
        let _ = std::fs::remove_file(path);
    }
}

/// Where a branch's lease receipt lives, or `None` where there is no branch to
/// key on — a detached HEAD has none, and inventing one would key a receipt to a
/// name no later reader could reconstruct.
fn lease_receipt_path(root: &Path, branch: &str) -> Option<std::path::PathBuf> {
    if branch.is_empty() {
        return None;
    }
    let git_dir = git::git_dir(root).ok()?;
    Some(
        git_dir
            .join("batten-receipts")
            .join(format!("lease.{}", branch.replace('/', "-"))),
    )
}

fn run_mutate(
    command: cli::MutateCommand,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    // ABSOLUTE, and this is a defect rather than tidiness. Every suite runs with
    // its cwd inside the STAGED tree, so a relative root reaches the child as a
    // path resolved against the copy: the vendored runner is not there under
    // `./tests/…`, and `CARGO_TARGET_DIR=./target` would put the build inside
    // the tree being mutated. Measured on the first live sweep, which could not
    // run `./tests/bats/bin/bats` at all.
    let anchor = hook_authority_root();
    let resolved = anchor.canonicalize().unwrap_or_else(|_| anchor.to_owned());
    let root: &Path = &resolved;
    let names = match mutate::enforced_set() {
        Ok(names) => names,
        Err(reason) => {
            writeln!(err, "::error:: mutate: {reason}")?;
            return Ok(ExitCode::Usage);
        }
    };
    match command {
        cli::MutateCommand::Census => {
            let census = mutate::census(root, &names);
            for (subject, verdict) in &census.findings {
                writeln!(out, "{subject} {verdict}")?;
            }
            if census.findings.is_empty() {
                // THE UNDECLARED ENGINE COUNT RIDES THE CLEAN LINE (CLOUD-1369),
                // because a route that landed with nothing reporting its
                // population would make "the backlog is what the census will
                // then report" false. A count is a sensor: it names no module
                // (rule 4) and it refuses nothing, so the exit code is unmoved.
                writeln!(
                    out,
                    "mutate census: {} gate(s), every one enforced or exempt by a filed row; {} \
                     engine module(s) declare nothing and are outside the censused set",
                    census.subjects, census.engine_undeclared
                )?;
                return Ok(ExitCode::Success);
            }
            writeln!(
                err,
                "::error:: mutate census: {} violation(s) over {} gate(s) — a gate outside the \
                 enforced set is covered by nothing stronger than \"its suite is green\", which \
                 CLOUD-418 measured as insufficient four times. Declare a #MUTANT row and add the \
                 name, or carry a #MUTANT-EXEMPT naming the issue that owns the gap.",
                census.findings.len(),
                census.subjects
            )?;
            Ok(ExitCode::Violation)
        }
        cli::MutateCommand::Sweep => {
            // The staged tree lives beside the build artefacts rather than in
            // the system temporary directory, and it PERSISTS between runs. Both
            // are the same economy: a declared suite can be a compiled tier, and
            // a tree re-created from scratch every sweep would rebuild the whole
            // crate every sweep. `Staged::new` prunes what the tracked set no
            // longer names and re-copies only what differs, so a persisted tree
            // still carries exactly the tracked bytes.
            let work = root.join("target").join("mutate");
            std::fs::create_dir_all(&work)?;
            let sweep = match mutate::sweep(root, &names, work) {
                Ok(sweep) => sweep,
                Err(reason) => {
                    writeln!(err, "::error:: mutate: {reason}")?;
                    return Ok(ExitCode::Internal);
                }
            };
            for finding in &sweep.findings {
                writeln!(out, "{finding}")?;
            }
            let code = sweep.code();
            if code == ExitCode::Success {
                writeln!(
                    out,
                    "mutate sweep: {} declared mutation(s) across {} gate(s), every one caught",
                    sweep.declared, sweep.gates
                )?;
                return Ok(code);
            }
            // THE TWO CLASSES ARE COUNTED APART. A could-not-look is not a
            // suite that passed on broken code — it is a suite nothing could
            // ask — and adding them produced `124 of 0 declared mutation(s) …
            // were not caught`, a coverage verdict over a denominator of zero.
            let unlooked = sweep.unlooked();
            let uncaught = sweep.findings.len() - unlooked;
            if uncaught > 0 {
                writeln!(
                    err,
                    "::error:: mutate sweep: {} of {} declared mutation(s) across {} gate(s) were \
                     not caught — a suite that passes on broken code is not coverage",
                    uncaught, sweep.declared, sweep.gates
                )?;
            }
            if unlooked > 0 {
                writeln!(
                    err,
                    "::error:: mutate sweep: {unlooked} declared mutation(s) could not be looked \
                     at — an unresolvable gate or suite is not a pass"
                )?;
            }
            Ok(code)
        }
    }
}

fn run_semver(
    command: SemverCommand,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        SemverCommand::Check {
            baseline,
            release_type,
            package,
        } => run_semver_check(
            baseline.as_deref(),
            release_type.as_deref(),
            package.as_deref(),
            mode,
            out,
            err,
        ),
    }
}

/// `batten semver check`: is this branch's API delta compatible with its claim?
///
/// The rev route first, the lock route only when the report says the registry
/// could not resolve. `crate::semver` states why that fallback exists and why it
/// applies more of the gate rather than less.
fn run_semver_check(
    baseline: Option<&str>,
    release_type: Option<&str>,
    package: Option<&str>,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let root = &hook_authority_root();
    let baseline = baseline.unwrap_or("origin/main");
    let release_type = release_type.unwrap_or("patch");
    let package = package.unwrap_or("batten");
    let Some(toolchain) = semver::toolchain(root) else {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            "semver: no rustc on PATH, so the toolchain the comparison must run under could not be determined. This is a checkout problem, not a verdict.",
        )?;
        return Ok(ExitCode::Usage);
    };
    let mut reason = None;
    let Some(compared) = semver_compare(
        root,
        &toolchain,
        package,
        baseline,
        release_type,
        &mut reason,
    ) else {
        let why = reason.unwrap_or_else(|| String::from("the comparison could not be run at all"));
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("semver: {why}, so this is not a pass."),
        )?;
        return Ok(ExitCode::Usage);
    };
    let commits = semver_commits(root, baseline);
    let verdict = semver::reconcile(&compared, &commits);
    let route = compared.route.as_str();
    let lints = compared.lints().join(" ");
    match &verdict {
        semver::Verdict::Compatible => writeln!(
            out,
            "semver: the API delta is {release_type}-compatible for {package} (baseline {baseline}, route {route})"
        )?,
        semver::Verdict::Declared(sha) => writeln!(
            out,
            "semver: breaking change DECLARED by {sha} — {lints} (baseline {baseline}, route {route})"
        )?,
        semver::Verdict::Undeclared => {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!(
                    "semver: this branch breaks the {package} API but no commit declares it. Failing lint(s): {lints}. Mark the break in Conventional Commits — a `!` before the colon, or a `BREAKING CHANGE:` footer — or keep the change {release_type}-compatible."
                ),
            )?;
            // THE SUBJECTS, one per line, because the line above names a CLASS
            // and the author has to find the INSTANCE. Without these the remedy
            // is "run the delegated tool yourself and read its report", over a
            // report this process already holds.
            for subject in compared.subjects(root) {
                output::message(mode, Verbosity::Normal, err, &format!("  {subject}"))?;
            }
        }
        semver::Verdict::CouldNotLook => output::message(
            mode,
            Verbosity::Normal,
            err,
            "semver: the comparison did not complete, or graded nothing, so this is not a pass.",
        )?,
    }
    Ok(verdict.code())
}

/// Run the comparison, taking the lock route only when the rev route could not
/// RESOLVE — never when it merely refused.
fn semver_compare(
    root: &Path,
    toolchain: &str,
    package: &str,
    baseline: &str,
    release_type: &str,
    reason: &mut Option<String>,
) -> Option<semver::Compared> {
    let first = semver::against_rev(root, toolchain, package, baseline, release_type)?;
    if !first.unresolvable() {
        return Some(first);
    }
    // The registry could not satisfy the scratch resolve. The baseline is still
    // buildable from the lock it committed, so build it there instead.
    // Under `target/`, beside `cargo-semver-checks`' own `target/semver-checks/`
    // scratch. A build artefact belongs where the build artefacts are: it is
    // gitignored already, and `target-prune` reclaims it with everything else
    // rather than growing without bound in a state directory nobody prunes.
    let scratch = root.join("target").join("semver-baseline");
    drop(std::fs::remove_dir_all(&scratch));
    std::fs::create_dir_all(&scratch).ok()?;
    // THE HEAD SIDE IS BUILT FROM THE LOCK TOO, and this is the half the fallback
    // was missing (CLOUD-1399). The tool generates the current crate's rustdoc the
    // same way it generates the baseline's — a scratch package with no lock — so a
    // registry index ahead of the committed lock breaks BOTH sides, and replacing
    // only the baseline left the run failing for the reason it already was.
    //
    // Its own directory beside the baseline's: both are in flight in one run, and
    // a shared `CARGO_TARGET_DIR` would have them overwrite each other's
    // `{package}.json`.
    //
    // A head side that will not build is NOT fatal here. It is handed over as
    // `None`, and the tool falls back to generating it itself — which is the path
    // that was failing, so this degrades to the previous behaviour rather than to
    // no comparison. The verdict stays could-not-look either way; what changes is
    // that the run gets a chance to succeed first.
    let head_scratch = root.join("target").join("semver-current");
    drop(std::fs::remove_dir_all(&head_scratch));
    let current = std::fs::create_dir_all(&head_scratch)
        .ok()
        .and_then(|()| semver::current_rustdoc(root, toolchain, package, &head_scratch).ok());
    match semver::baseline_rustdoc(root, toolchain, package, baseline, &scratch) {
        Ok(rustdoc) => semver::against_rustdoc(
            root,
            toolchain,
            package,
            &rustdoc,
            current.as_deref(),
            release_type,
        ),
        Err(why) => {
            // The caller renders could-not-look either way; this is what makes it
            // legible. A gate that cannot say WHY it could not look is the one
            // shape this repository refuses to ship.
            *reason = Some(why);
            None
        }
    }
}

/// The branch's own commits, which are the only ones that may declare its break.
///
/// A declaration that already landed on the baseline licenses nothing here, and
/// that is the retired suite's own case carried rather than re-derived.
///
/// Composed from the two readers `git.rs` already has rather than a third:
/// `subjects_in_range` walks the range once for the sha and `%s`, and
/// `commit_record` carries `%B` for the footer spelling.
fn semver_commits(root: &Path, baseline: &str) -> Vec<semver::Commit> {
    let Ok(subjects) = crate::git::subjects_in_range(root, baseline, "HEAD") else {
        return Vec::new();
    };
    subjects
        .into_iter()
        .map(|found| semver::Commit {
            body: crate::git::commit_record(root, &found.commit)
                .map(|record| record.body)
                .unwrap_or_default(),
            sha: found.commit.chars().take(8).collect(),
            subject: found.subject,
        })
        .collect()
}

/// The articulation clause over whichever mode `commit check` is running in
/// (CLOUD-1278).
///
/// # Why this is a second pass rather than a wider `Subject`
///
/// The convention clause reads one line; this one reads the whole message AND the
/// paths the commit moved. Widening `Subject` to carry both would charge every
/// consumer of the subject clause a tree walk per commit for a field it does not
/// read, and `commit::Subject` is what `read_message` returns before a commit
/// exists — a shape with no paths to put in it.
///
/// # A repository declaring no protected paths is judged, and passes
///
/// The glob list being empty makes [`git::writes_in_range`] select nothing, so
/// every commit yields no paths and no finding. That is the honest answer rather
/// than a short-circuit: a consumer that protects nothing has nothing to
/// articulate, and the distinction only matters if somebody later reads a clean
/// run as evidence the clause fired.
fn commit_admissions(
    range: Option<&str>,
    message: Option<&str>,
    overrides: &Overrides,
) -> Result<Vec<commit::Finding>> {
    let root = Path::new(".");
    let protected = resolve::resolve(root, overrides)?.protected.clone();
    match (range, message) {
        (Some(range), None) => {
            // Already validated above; re-split rather than threaded, because a
            // second parameter carrying a value derived from an existing one is a
            // second chance for the two to disagree.
            let Some((base, head)) = range.split_once("..") else {
                return Ok(Vec::new());
            };
            Ok(commit::judge_admissions(&git::writes_in_range(
                root, base, head, &protected,
            )?))
        }
        (None, Some(message)) => {
            let body = std::fs::read_to_string(message).map_err(|error| {
                UsageError::raise(format!(
                    "commit check: cannot read the commit message file `{message}`: {error}"
                ))
            })?;
            // The STAGED set, narrowed to the protected globs by the same
            // `Selector` the range half walks with — one authority on "does this
            // glob select this path", never a second matcher here.
            let selectors = protected
                .iter()
                .map(|glob| rules::Selector::new(glob))
                .collect::<Result<Vec<_>>>()?;
            let staged = git::staged_paths(root)?
                .into_iter()
                .filter(|path| selectors.iter().any(|selector| selector.matches(path)))
                .collect();
            Ok(commit::judge_pending(&body, &staged))
        }
        // Both modes and neither are refused above, before this is reached.
        _ => Ok(Vec::new()),
    }
}

/// The `[rule.conserves]` arm tokens one revision of the config declares, keyed
/// by the token and carrying the config path a reader would open (CLOUD-1402).
///
/// # Keyed by the TOKEN, never by the rule id
///
/// The hazard is a token becoming spendable, so that is the thing whose arrival
/// is the event. Keying by rule id would re-introduce every arm of a rule that
/// was merely RENAMED, and a commit that renamed a rule and added a ledger row
/// would be refused for a widening that never happened.
///
/// # A config this build cannot parse contributes NOTHING
///
/// This clause's question is which arms are NEW, and a parent revision that will
/// not parse is could-not-look about that comparison rather than a verdict on the
/// commit. [`config::parse_base`] is the reader for the same reason
/// `--config-from` uses it: a parent may legitimately declare a key this build has
/// since retired, and refusing there would make retiring a key unlandable. The
/// head side of every other clause in the same run parses the config strictly, so
/// a genuinely broken config is already refused — loudly, and with the key named.
fn conserves_arms(text: &str, source: &str) -> std::collections::BTreeMap<String, String> {
    let mut arms = std::collections::BTreeMap::new();
    let Ok(parsed) = config::parse_base(text, source) else {
        return arms;
    };
    for rule in &parsed.rules {
        let Some(conserves) = rule.conserves.as_ref() else {
            continue;
        };
        // Every arm, not only the two optional ones. `carried`, `subsumed` and
        // `changed` are required columns so they cannot arrive on an existing
        // table — but they can arrive with a table, and a new ledger that spends
        // its own arm in the same commit is the same self-authorization.
        let declared = [
            ("carried", Some(conserves.carried.clone())),
            ("subsumed", Some(conserves.subsumed.clone())),
            ("changed", Some(conserves.changed.clone())),
            ("withdrawn", conserves.withdrawn.clone()),
            ("ported", conserves.ported.clone()),
        ];
        for (arm, token) in declared {
            let Some(token) = token else {
                continue;
            };
            // First declarer wins the pointer. Two rules spelling one token is
            // one token arriving, so which row a reader is sent to is a
            // presentation choice; keeping it deterministic is what §6 asks for.
            arms.entry(token)
                .or_insert_with(|| format!("{}.{arm}", rule.id));
        }
    }
    arms
}

/// The lines `rev` added to `path` relative to `parent`, as a set difference.
///
/// A set rather than a diff hunk walk: the question is whether a line carrying a
/// newly-declared token exists here and did not exist before, and a token that is
/// new to the config cannot appear in the parent's text at all — so the cheap
/// answer is the exact one. Absent at either side is the empty text, which is the
/// right reading in both directions: a path this commit CREATED has every line
/// added, and one it deleted has none.
fn lines_added(root: &Path, parent: &str, rev: &str, path: &str) -> Vec<String> {
    let at = |reference: &str| match git::read_at(root, reference, path) {
        Ok(git::BaseBlob::Found { text, .. }) => Some(text),
        // Absent at a ref that resolved is a measured nothing. An unresolvable ref
        // is could-not-look and is handled by the caller, which does not reach
        // here for one.
        Ok(_) => Some(String::new()),
        Err(_) => None,
    };
    let (Some(before), Some(after)) = (at(parent), at(rev)) else {
        return Vec::new();
    };
    let held: std::collections::BTreeSet<&str> = before.lines().collect();
    after
        .lines()
        .filter(|line| !held.contains(line))
        .map(str::to_owned)
        .collect()
}

/// The sequencing clause over whichever mode `commit check` is running in
/// (CLOUD-1402).
///
/// # Where the globs come from, and why that is not circular
///
/// The ledger's `declared_in` globs are read from the WORKING TREE's config, as
/// every other clause in this run reads it, and the arm SETS are read from the
/// config at each commit and its parent. The two are different questions: which
/// files could carry a ledger row is a fact about this checkout's policy, and
/// which arms are new is a fact about one commit. Reading the globs per commit
/// would let a commit narrow the glob and hide its own spend.
///
/// # Could-not-look never fabricates a refusal
///
/// A parent that does not resolve — a root commit, or a shallow boundary — leaves
/// the commit unjudged rather than reading every arm it declares as introduced.
/// That is the direction a miss must fail in: the alternative refuses the first
/// commit of every repository.
fn commit_arm_sequencing(
    range: Option<&str>,
    message: Option<&str>,
    overrides: &Overrides,
) -> Result<Vec<commit::Finding>> {
    let root = Path::new(".");
    let resolved = resolve::resolve(root, overrides)?;
    let ledgers: Vec<String> = resolved
        .rules
        .iter()
        .filter_map(|rule| rule.conserves.as_ref())
        .map(|conserves| conserves.declared_in.clone())
        .collect();
    // A consumer declaring no ledger has no arm to introduce, so there is nothing
    // to judge and the honest answer is an empty finding set rather than a walk.
    if ledgers.is_empty() {
        return Ok(Vec::new());
    }
    let selectors = ledgers
        .iter()
        .map(|glob| rules::Selector::new(glob))
        .collect::<Result<Vec<_>>>()?;

    let mut globs = ledgers.clone();
    globs.push(config::CONFIG_FILE.to_owned());

    match (range, message) {
        (Some(range), None) => {
            let Some((base, head)) = range.split_once("..") else {
                return Ok(Vec::new());
            };
            let mut sequences = Vec::new();
            for write in git::writes_in_range(root, base, head, &globs)? {
                // A commit that did not touch the config declared no arm, so the
                // introduced set is empty by construction and neither blob is
                // read. This is what keeps the clause free on the overwhelming
                // majority of commits.
                if !write.paths.contains(config::CONFIG_FILE) {
                    continue;
                }
                let parent = format!("{}^", write.commit);
                let Ok(git::BaseBlob::Found { .. }) =
                    git::read_at(root, &parent, config::CONFIG_FILE)
                else {
                    // Either the parent does not resolve, or it carried no config
                    // at all. The first is could-not-look; the second is a
                    // repository adopting Batten, where every arm is new and no
                    // ledger can predate it. Both leave the commit unjudged.
                    continue;
                };
                sequences.push(arm_sequence(
                    root,
                    &parent,
                    &write.commit,
                    commit_label(&write.commit),
                    &write.paths,
                    &selectors,
                ));
            }
            Ok(commit::judge_arm_sequencing(&sequences))
        }
        (None, Some(_)) => {
            // The pending twin, and the earliest computable moment: the index is
            // the commit-to-be and `HEAD` is its parent, so a refusal here means
            // the self-authorizing commit is never created.
            let staged = git::staged_paths(root)?;
            if !staged.contains(config::CONFIG_FILE) {
                return Ok(Vec::new());
            }
            let index = git::staged_facts(root, &[config::CONFIG_FILE.to_owned()])?;
            let Some(after) = index.get(config::CONFIG_FILE) else {
                return Ok(Vec::new());
            };
            let Ok(git::BaseBlob::Found { text: before, .. }) =
                git::read_at(root, "HEAD", config::CONFIG_FILE)
            else {
                return Ok(Vec::new());
            };
            let introduced = introduced_arms(&before, after);
            if introduced.is_empty() {
                return Ok(Vec::new());
            }
            let ledger_paths: Vec<String> = staged
                .iter()
                .filter(|path| selectors.iter().any(|selector| selector.matches(path)))
                .cloned()
                .collect();
            let indexed = git::staged_facts(root, &ledger_paths)?;
            let mut added_lines = Vec::new();
            for path in &ledger_paths {
                let held: std::collections::BTreeSet<String> =
                    match git::read_at(root, "HEAD", path) {
                        Ok(git::BaseBlob::Found { text, .. }) => {
                            text.lines().map(str::to_owned).collect()
                        }
                        Ok(_) => std::collections::BTreeSet::new(),
                        Err(_) => continue,
                    };
                if let Some(text) = indexed.get(path) {
                    added_lines.extend(
                        text.lines()
                            .filter(|line| !held.contains(*line))
                            .map(str::to_owned),
                    );
                }
            }
            Ok(commit::judge_arm_sequencing(&[commit::ArmSequence {
                label: "pending".to_owned(),
                introduced,
                added_lines,
            }]))
        }
        // Both modes and neither are refused before this is reached.
        _ => Ok(Vec::new()),
    }
}

/// The arms `after` declares that `before` did not, keyed by the config pointer.
fn introduced_arms(before: &str, after: &str) -> std::collections::BTreeMap<String, String> {
    let held = conserves_arms(before, "the parent revision's batten.toml");
    conserves_arms(after, config::CONFIG_FILE)
        .into_iter()
        .filter(|(token, _)| !held.contains_key(token))
        .map(|(token, pointer)| (pointer, token))
        .collect()
}

/// One commit's two sets, resolved.
fn arm_sequence(
    root: &Path,
    parent: &str,
    rev: &str,
    label: String,
    paths: &std::collections::BTreeSet<String>,
    selectors: &[rules::Selector],
) -> commit::ArmSequence {
    let before = git::show(root, parent, config::CONFIG_FILE).unwrap_or_default();
    let after = git::show(root, rev, config::CONFIG_FILE).unwrap_or_default();
    let introduced = introduced_arms(&before, &after);
    if introduced.is_empty() {
        // No arm arrived, so no line can spend one. Returning early keeps the
        // ledger's blobs unread on every commit that merely edited the config.
        return commit::ArmSequence {
            label,
            ..commit::ArmSequence::default()
        };
    }
    let mut added_lines = Vec::new();
    for path in paths
        .iter()
        .filter(|path| selectors.iter().any(|selector| selector.matches(path)))
    {
        added_lines.extend(lines_added(root, parent, rev, path));
    }
    commit::ArmSequence {
        label,
        introduced,
        added_lines,
    }
}

/// A commit's short form, as every other pointer in this repository renders it.
fn commit_label(sha: &str) -> String {
    sha.chars().take(8).collect()
}

fn run_commit_check(
    json: bool,
    range: Option<&str>,
    message: Option<&str>,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    // Exactly one mode. Both is ambiguous, and neither is a run over nothing that
    // would exit 0 — the vacuous pass a gate must never produce.
    let subjects = match (range, message) {
        (Some(_), Some(_)) => {
            return Err(UsageError::raise(
                "commit check: a range and --message name two different objects; pass one"
                    .to_owned(),
            ));
        }
        (None, None) => {
            return Err(UsageError::raise(
                "commit check: pass <base>..<head> or --message <file>; with neither there is \
                 nothing to judge"
                    .to_owned(),
            ));
        }
        (Some(range), None) => {
            let (base, head) = range.split_once("..").ok_or_else(|| {
                UsageError::raise(format!(
                    "commit check: `{range}` is not a <base>..<head> range"
                ))
            })?;
            commit::read_range(Path::new("."), base, head)?
        }
        (None, Some(message)) => vec![commit::read_message(Path::new(message))?],
    };

    let mut findings = commit_policy(overrides)?.judge(&subjects)?;
    findings.extend(commit_admissions(range, message, overrides)?);
    findings.extend(commit_arm_sequencing(range, message, overrides)?);

    if json {
        // Emitted unconditionally, including for a clean run: JSON that is
        // sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&findings)?)?;
    } else {
        // Silence is the success signal on the human channel (§6).
        write!(out, "{}", commit::report(&findings))?;
    }
    Ok(ExitCode::verdict(!findings.is_empty()))
}

/// Dispatch the `attribution` subtree.
///
/// Split out of [`run`] rather than matched inline: the gate half now threads a
/// harness through (CLOUD-276), and `run` is at its line ceiling — a dispatcher
/// that grows every time one verb gains an argument is the shape that ceiling
/// exists to catch.
fn run_attribution(
    command: AttributionCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        AttributionCommand::Check {
            json,
            range,
            message,
            harness,
        } => run_attribution_check(
            json,
            range.as_deref(),
            message.as_deref(),
            harness,
            overrides,
            out,
        ),
        AttributionCommand::Identity => run_attribution_identity(overrides, err),
    }
}

fn run_attribution_check(
    json: bool,
    range: Option<&str>,
    message: Option<&str>,
    harness: Option<hook::Harness>,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    // Exactly one mode. Both is ambiguous and neither is a run over nothing that
    // would exit 0 — the vacuous pass a gate must never produce.
    let commits = match (range, message) {
        (Some(_), Some(_)) => {
            return Err(UsageError::raise(
                "attribution check: --range and --message name two different objects; pass one"
                    .to_owned(),
            ));
        }
        (None, None) => {
            return Err(UsageError::raise(
                "attribution check: pass --range <base>..<head> or --message <file>; with neither \
                 there is nothing to judge"
                    .to_owned(),
            ));
        }
        (Some(range), None) => {
            let (base, head) = range.split_once("..").ok_or_else(|| {
                UsageError::raise(format!(
                    "attribution check: `{range}` is not a <base>..<head> range"
                ))
            })?;
            attribution::read_range(Path::new("."), base, head)?
        }
        (None, Some(message)) => {
            vec![attribution::read_message(
                Path::new("."),
                Path::new(message),
            )?]
        }
    };

    let policy = attribution_policy(overrides)?;
    let mut findings = Vec::new();
    for commit in &commits {
        findings.extend(policy.judge(commit)?);
    }

    if json {
        // Emitted unconditionally, including for a clean run: JSON that is
        // sometimes absent is unparseable.
        //
        // `None` for both candidate values, and stated rather than left to be
        // inferred: this verb's input is a commit range or a message file, and
        // neither carries a model identity or a session. The offered-value arms of
        // `attribution::capture` — where a declaration REFUSES a value the host
        // did supply — belong to a surface that reads a host payload, which is the
        // provenance record CLOUD-275 owns. They are pinned at the library surface
        // instead, not left unpinned.
        let document = AttributionDocument {
            caller: match harness {
                Some(harness) => attribution::capture(harness, None, None),
                // No host named: three degraded values, which is a different
                // claim from any host's row and must not read as one.
                None => decision::Caller::undeclared(),
            },
            expects: harness
                .map(|harness| {
                    attribution::expectations(harness)
                        .into_iter()
                        .map(|(capability, declares)| Expectation {
                            capability,
                            declares,
                        })
                        .collect()
                })
                .unwrap_or_default(),
            findings: &findings,
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
    } else {
        // Silence is the success signal on the human channel (§6).
        write!(out, "{}", attribution::report(&findings))?;
    }
    Ok(ExitCode::verdict(!findings.is_empty()))
}

fn run_attribution_identity(overrides: &Overrides, err: &mut dyn Write) -> Result<ExitCode> {
    let policy = attribution_policy(overrides)?;
    let outcome = attribution::set_identity(Path::new("."), &policy)?;
    // The report goes to stderr: this is a statement about what Batten did to the
    // clone, not a verdict about the repository, and §6 keeps those channels
    // apart.
    writeln!(err, "{}", outcome.line(&policy.identity))?;
    Ok(ExitCode::Success)
}

/// What a fail-open boundary says on its way out.
///
/// Loud, not silent (CLOUD-43). A guard that cannot read its input is a gate
/// that did not run, and the silent version of that is byte-identical to a clean
/// allow — the false green this engine exists to catch, in the one place nobody
/// would think to look. They go through [`output::message`], so they are
/// `batten: `-prefixed and ladder-gated: this is a statement about Batten, not a
/// verdict, which is exactly the distinction [`output::verdict`]'s unprefixed,
/// ungated shape draws in the other direction.
const UNREADABLE_STDIN: &str =
    "hook: stdin could not be read, so nothing was adjudicated — allowing";
const UNDECODABLE_PAYLOAD: &str =
    "hook: the payload on stdin did not decode, so nothing was adjudicated — allowing";

/// Adjudicate one mediated call read from stdin (CLOUD-202).
///
/// Fail open at every boundary — unreadable stdin, an undecodable payload, an
/// envelope with no command all allow: a guard must never be the reason a
/// session cannot proceed. The bypass env var is the same hatch the shell
/// guards honour, resolved here at the boundary so the core stays pure.
///
/// The deny channel is per-harness — the number is not. The Claude Code adapter
/// answers in the host's JSON decision object (exit 0), where the document *is*
/// the deny; the neutral exit-code adapter denies with [`ExitCode::Violation`],
/// the same code a `check` violation returns, carrying its reason to stderr
/// through [`Denial`] so the write stays at the binary boundary.
/// Print one allowlisted payload field, or nothing (CLOUD-479).
///
/// SILENT ON EVERY FAILURE, and that is the contract rather than an oversight:
/// the callers are shell hooks whose next line is `[ -n "$x" ] || exit 0`, so an
/// unreadable stdin, an undecodable payload and an absent field must all arrive
/// as the same empty answer they get from `jq -r '.x // empty'` today. Anything
/// louder would turn a fail-open guard into one that reports on payloads it was
/// never meant to judge.
///
/// The failure a caller genuinely must NOT miss — the binary being absent
/// entirely — cannot reach this function, and since CLOUD-824 there is no
/// launcher to report it either. `mise-tasks/stop-guard.sh` and
/// `mise-tasks/contract-drift.sh` still carry that half themselves, which is the
/// shape they always had; what is gone is the shell copy they inherited it from.
///
/// Exit is always `Success`: this renders no verdict, so it has none to signal.
fn run_hook_field(
    harness: hook::Harness,
    field: hook::Field,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return Ok(ExitCode::Success);
    }
    if let Some(value) = hook::field(harness, &raw, field) {
        writeln!(out, "{value}")?;
    }
    Ok(ExitCode::Success)
}

/// The receipt verdicts this call's required checks resolve to, read at the
/// boundary.
///
/// Lifted out of [`run_hook`] rather than left inline because that function is
/// held to clippy's 100-line ceiling and this is a self-contained question: what
/// do the receipt store and the agent's own records say about the checks this
/// call's rows require. Everything here LOOKS; `adjudicate` decides — the split
/// the whole boundary keeps, so nothing in this function judges anything.
///
/// `None` throughout means "could not look", which allows.
/// A declared recency bound and the clock it is read against (CLOUD-1170).
///
/// **One value rather than two parameters, and not only for the argument
/// ceiling.** `receipt::verdicts` already describes them as one thing —
/// *"`max_ages` carries CLOUD-988's declared bounds, and `now` is the clock those
/// bounds are read against"* — and they are never useful apart: a bound with no
/// clock cannot be compared, and a clock with no bound is read by nobody. Passing
/// them separately let the clock be filled in at the point of use, which is
/// exactly how the one remaining boundary clock READ survived CLOUD-988.
#[derive(Clone, Copy)]
struct Recency<'a> {
    /// CLOUD-988's declared bounds, per check.
    max_ages: &'a std::collections::BTreeMap<String, u64>,
    /// The instant those bounds are read against.
    ///
    /// **Supplied by the caller when `--instant` named one** (CLOUD-1170), and
    /// the boundary's own clock otherwise. A supplied instant makes the
    /// comparison reproducible — the same instant over the same tree yields the
    /// same `Validity`, which a clock read never can — and absent means what it
    /// always meant, so no committed row changes meaning by this arriving.
    now: std::time::SystemTime,
}

fn receipt_facts(
    policy: &hook::Policy,
    envelope: &hook::Envelope,
    sourced: &[(&String, &rules::ReceiptKey)],
    store: Option<&receipt::SourcedStore>,
    receipted: &std::collections::BTreeMap<String, rules::ReceiptKey>,
    recency: &Recency<'_>,
    judgeable: bool,
) -> hook::ReceiptFacts {
    let &Recency { max_ages, now } = recency;
    // The two non-answers are DIFFERENT answers, and CLOUD-787 is where they
    // stopped being one. `IsNot` is the boundary having looked: no required
    // check selected this call, or the write lands somewhere policy does not
    // judge. `CouldNotLook` is further down, where the receipt store itself
    // could not be read. Both allow, and they are not the same fact.
    //
    // `sourced` and `receipted` are the partition of the required set, so their
    // both being empty IS "no required check selected this call" — read from the
    // two halves rather than from a third parameter carrying the union, which
    // clippy's argument ceiling is right to refuse and which was a second
    // spelling of one fact besides.
    if (sourced.is_empty() && receipted.is_empty()) || !judgeable {
        return facts::Look::IsNot;
    }
    let mut verdicts = if receipted.is_empty() {
        // Nothing to ask the receipt store, having looked: there simply were no
        // receipt-keyed checks among the ones required. An EMPTY map, not a
        // non-answer — the agent-sourced loop below fills it in.
        Some(std::collections::BTreeMap::new())
    } else {
        // The subject a `named`-keyed row files under, resolved HERE because
        // `receipt::verdicts` has no envelope and `adjudicate` may not open a
        // file (CLOUD-987). One value per call: a mediated call names one
        // subject, so the declaring rows cannot disagree about which.
        // The clock is handed in, never taken inside (CLOUD-988), and it is read
        // only when a row declared a bound — an empty `max_ages` means no
        // `SystemTime::now()` and no `stat` on the hottest path in the binary.
        //
        // The field bounds are resolved HERE rather than handed in beside
        // `max_ages`, and the reason is the one the comment above already gives
        // for reading the partition off two parameters instead of three: this
        // function is at clippy's argument ceiling, and the bound is derivable
        // from the two things it already holds. `max_ages` has to travel because
        // the agent-sourced loop below reads it too; this is read once, on the
        // one branch that has a receipt file to open at all.
        receipt::verdicts(
            receipted,
            policy.named_receipt_subject(envelope).as_deref(),
            max_ages,
            &policy.field_bound_for(envelope),
            now,
        )
    };
    // Each agent-sourced check, decided by the pure predicate over the record
    // the boundary just read. `Look::Is` is the only answer that satisfies a
    // check; never-ran and command-mismatch both arrive as `Missing`, which
    // is the deny that carries the `Fix::Run` asking for the command.
    //
    // A store the boundary could not build takes the WHOLE call to
    // could-not-look (CLOUD-859), rather than leaving these checks out of the
    // map. Leaving them out is not a softer answer: `receipt_rules` reads an
    // absent verdict as `Missing` — deliberately, since a boundary that answered
    // for fewer checks than a row requires has not proved the precondition — so
    // an omission is the strictest answer available, and it would make a
    // checkout with no resolvable HEAD refuse every `gh pr ready` for a property
    // of the environment. This is `receipt::verdicts`'s own posture, where an
    // unresolvable branch takes the call to could-not-look for the same reason.
    if !sourced.is_empty() && store.is_none() {
        return facts::Look::CouldNotLook;
    }
    if let (Some(verdicts), Some(store)) = (verdicts.as_mut(), store) {
        for (check, _) in sourced {
            let Some(declared) = policy.agent_fact(check) else {
                continue;
            };
            let record = store.record(check);
            let verdict = match facts::sourced(record.as_ref(), declared.answered_by()) {
                facts::Look::Is(_) => receipt::Validity::Valid,
                facts::Look::IsNot | facts::Look::CouldNotLook => receipt::Validity::Missing,
            };
            // THE AGE IS READ LAST AND ONLY OVER A VALID RECORD, exactly as
            // `receipt::verdicts` reads it (CLOUD-988): a record already Missing
            // has a more specific answer and a different remedy — *run it*,
            // where this one says *run it again* — and a repository declaring no
            // bound pays no `stat`.
            let verdict = match (verdict, max_ages.get(*check)) {
                (receipt::Validity::Valid, Some(&max_age))
                    if store.expired(check, max_age, now) =>
                {
                    receipt::Validity::Expired
                }
                (verdict, _) => verdict,
            };
            verdicts.insert((*check).clone(), verdict);
        }
    }
    // A store the boundary could not read is the could-not-look arm — the one
    // case here that is genuinely "the question could not be asked".
    verdicts.map_or(facts::Look::CouldNotLook, facts::Look::Is)
}

/// Drop every row whose declared `bypass_env` is set in this process's
/// environment (CLOUD-437).
///
/// The environment read lives here rather than in [`hook`] for the reason every
/// other fact does: `adjudicate` is contractually pure, so the boundary looks and
/// the core decides. [`hook::Policy::declared_hatches`] hands back the names and
/// this answers which of them are set.
///
/// **Cheap when irrelevant** (house-style §4). A ruleset declaring no
/// `bypass_env` — every ruleset until one opts in — collects an empty set, reads
/// no environment variable, and clones no policy. This runs on the hottest path
/// in the binary, so that is a requirement rather than a nicety.
fn without_set_hatches(policy: hook::Policy) -> hook::Policy {
    let set: std::collections::BTreeSet<String> = policy
        .declared_hatches()
        .into_iter()
        .filter(|name| std::env::var_os(name).is_some_and(|value| !value.is_empty()))
        .map(std::borrow::ToOwned::to_owned)
        .collect();
    if set.is_empty() {
        return policy;
    }
    // The row is REMOVED rather than its refusal suppressed, so the rows behind
    // it still fire. See `hook::Policy::without_hatched`.
    policy.without_hatched(&set)
}

/// What a host that does not emit this event is told, split out of [`run_hook`]
/// when the end-of-turn clause pushed that function past the line ceiling.
///
/// Two sentences and no third: the host either degrades the event to one it does
/// emit, in which case a policy keyed on it still fires somewhere, or it does
/// not, in which case nothing keyed on it fires at all. Naming which of the two
/// happened is the whole content — an absent capability is a statement about the
/// host, never a refusal.
fn unsupported_event_note(
    harness: hook::Harness,
    capabilities: &hook::Capabilities,
    event: hook::Event,
) -> String {
    match capabilities.degrade(event) {
        Some(fallback) => format!(
            "{} does not emit {}; a policy keyed on it watches {} here",
            harness.as_str(),
            event.as_str(),
            fallback.as_str()
        ),
        None => format!(
            "{} does not emit {}; nothing keyed on it fires here",
            harness.as_str(),
            event.as_str()
        ),
    }
}

fn run_hook(
    harness: hook::Harness,
    // Resolved by the dispatch (CLOUD-1170) — see `Recency::now`.
    instant: std::time::SystemTime,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        output::message(mode, Verbosity::Normal, err, UNREADABLE_STDIN)?;
        return Ok(ExitCode::Success);
    }
    let bypass = std::env::var_os(hook::BYPASS_ENV).is_some_and(|value| !value.is_empty());
    let Some(mut envelope) = hook::decode(harness, &raw) else {
        output::message(mode, Verbosity::Normal, err, UNDECODABLE_PAYLOAD)?;
        return Ok(ExitCode::Success);
    };
    // THE WRITE TARGET IS READ AS THE REPOSITORY READS IT (CLOUD-1133), and this
    // is the one place that can do it: `decode` is pure and has no repository,
    // and the readers below — the protected gate, and any module over
    // `input.call.writes` — compare against repo-relative globs. Claude Code
    // sends an absolute `file_path`, so before this line every one of those
    // comparisons was against a string that could not match, and a live `Write`
    // to a protected path was allowed. A target outside the tree is untouched.
    envelope.relativise_writes(hook_authority_root());
    // The capability table, consulted before anything keys on the event
    // (CLOUD-45). A host that does not declare this event fires nothing and
    // allows — never an error, never a deny: an absent capability is a statement
    // about the host, and refusing the call would make Batten the reason a
    // session cannot proceed on a host that simply offers less.
    //
    // The note rides the ladder above `normal`, because on the hosts where this
    // is reachable it is the ordinary state rather than news.
    let capabilities = harness.capabilities();
    if !capabilities.emits(envelope.event) && envelope.event != hook::Event::Unrecognized {
        let note = unsupported_event_note(harness, &capabilities, envelope.event);
        output::message(mode, Verbosity::Verbose, err, &note)?;
        return Ok(ExitCode::Success);
    }
    // The advisory drain rides the BATCH boundary (CLOUD-79), and which event
    // that is on this host is the capability table's answer rather than a literal
    // here (CLOUD-389). `degrade` hands back `PostToolBatch` where the host emits
    // it and `PostTool` where it does not, so the exact boundary is used wherever
    // it exists and the coalescing window stays the fallback for the four
    // surveyed hosts that offer none.
    //
    // Asking through `degrade` rather than testing two events is what keeps the
    // rule in one place: a second `||` here would be a copy of the table that
    // could disagree with it, and the drain would then own a fact about hosts.
    //
    // It is not part of adjudication and cannot become part of it: `adjudicate`
    // stays a pure function of config plus argv, this is a side effect at the
    // boundary, and it returns nothing the decision reads. This boundary is where
    // it belongs precisely because no host offers a deny channel at either event
    // — an advisory surface at an event that cannot refuse anything is
    // structurally unable to block (house-style §0.3).
    //
    // Both advisory producers WRITE INTO one buffer rather than each emitting:
    // the channel is one document per call on every host that has one, so two
    // emits on the same batch would put two JSON documents on stdout and the
    // host would read the first and discard the rest. Coalescing here is also
    // the honest shape — they are two findings of one advisory, not two
    // channels.
    // TIERED SINCE CLOUD-896. Every producer carries the latency its content
    // demands, so the channel's ceiling can admit what must be answered soonest
    // rather than whichever producer the boundary happened to reach first.
    let mut advice: Vec<advisory::Advice> = Vec::new();
    collect_batch_advice(harness, &envelope, overrides, mode, err, &mut advice)?;
    // NOT EMITTED HERE ANY MORE (CLOUD-898). A third producer arrived — a
    // dispatched handler — and its answer does not exist until config is
    // resolved, which happens below. Emitting here would put a second JSON
    // document on stdout for any event where a handler also speaks, which is the
    // exact defect the coalescing above was added to fix. So the buffer is
    // filled here and drained at ONE site further down. Safe because nothing
    // between the two points returns early: the only escapes are `?` on a config
    // failure, which is exit 3, and losing an advisory on a run that could not
    // read its own authority is the correct trade.
    // Only now is config touched. Ordering the cheap refusals first is §4's
    // "cheap when irrelevant" applied to the hottest path in the binary — this
    // runs on every mediated tool call — and it is also what keeps a bypassed or
    // command-less call from being able to fail on an unrelated config error.
    //
    // "Command-less" is no longer the same claim as "nothing to judge": a write
    // tool carries a path and no command, and skipping the config load for it
    // is what made the write matcher unjudgeable even once `adjudicate` grew
    // the gate (CLOUD-312). The cheap-refusals-first ordering is intact — a
    // bypassed call, and a payload that is neither a command nor a write, still
    // never touch config.
    // THE OTHER HALF OF THE LOOP (CLOUD-776). A gate denied with `Fix::Run`; the
    // agent ran that command with its own binary; the harness is handing the
    // result back right now. Record what it said, so the retry has a fact.
    //
    // Before the config load below and deliberately cheap when irrelevant: the
    // recorder asks whether this call carries a result at all before it asks
    // policy anything, so a post-tool event for any other command — which is
    // nearly all of them, now that batten is registered on every surface — does
    // no config work here.
    //
    // Failure is silent by design. A hook that cannot write a fact must not
    // become the reason work stops; the retry will simply deny again with the
    // same `Fix::Run`, which is the safe direction and a visible one.
    if envelope.event == hook::Event::PostTool {
        record_post_tool(overrides, &envelope, harness, &mut advice);
    }
    // THE SAME CORRECTION AGAIN, ONE SELECTOR LATER (CLOUD-924). The paragraph
    // above records CLOUD-312 finding that "command-less" had stopped meaning
    // "nothing to judge" once a write could be judged, and widening this
    // condition is what made the write matcher reachable. A tool selector does
    // it a second time: a `mediated_call` row may now be keyed on the TOOL a
    // call names, and an MCP call, a `Read` and a `Task` spawn carry neither a
    // command nor a write — so a repository declaring such a row had its rows
    // loaded for no call that could match them, and `adjudicate` was handed
    // `Policy::declaring_nothing` however carefully its gate was written.
    //
    // **THE COST IS REAL AND IS PAID HERE RATHER THAN HIDDEN.** `perf`'s
    // `passthrough` arm is exactly this shape — a `Read` with a `file_path`,
    // no command, no write — and its below-`noop` reading came from taking the
    // skip. That reading is load-bearing (`.claude/rules/rust.md`), so it is
    // re-measured with `perf-pair` against the merge base rather than argued
    // about, and the number travels with the change.
    //
    // The cheap refusals stay first and stay cheap: a bypassed call still never
    // touches config, and so does every event that is not the adjudicated one.
    // What is no longer free is a PreToolUse call with a tool name, which is the
    // one shape a tool-keyed row exists to judge — buying that back would mean
    // knowing whether any such row is declared, which is a question only the
    // config can answer.
    // Named `adjudicable` rather than `judgeable`: the latter is taken a few
    // lines below for a different question — whether a WRITTEN PATH is one
    // policy judges at all — and two bindings one letter apart deciding
    // different things is how a later edit reads the wrong one.
    //
    // THE SAME CORRECTION A THIRD TIME, AND IT WAS A DEAD GATE (CLOUD-1051). A
    // `Stop` payload carries no command, no write and no tool name, so this
    // predicate was false for every end of turn and the config was never loaded
    // there — which meant `Policy::declaring_nothing`, no bundles, and a
    // `mediated_call` module registered for the one moment that projects
    // `final-message` could not run at all. `policy/stop-posture.rego` shipped
    // in exactly that state and its own suite stayed green throughout, because a
    // `with input as` case fabricates the shape the boundary never built.
    //
    // The cost is one config load per TURN, not per call, and it buys the whole
    // end-of-turn surface. The retired shell hook this replaces paid ~330-440ms
    // at the same boundary; `perf`'s `passthrough` and `noop` arms are pre-tool
    // shapes and are untouched by this clause.
    let adjudicable = !envelope.command.is_empty()
        || envelope.writes.is_some()
        || envelope.event == hook::Event::Stop
        // A FOURTH TIME, and for a mint rather than a verdict (CLOUD-856). Session
        // start carries no command, no write and no tool name, so this predicate
        // was false there and config was never loaded — which means the receipt
        // this event exists to mint could not know which manifests were declared.
        // The cost is one config load per SESSION, not per call, which is the
        // same trade the `Stop` clause above makes, and it buys the whole reason
        // `Fact::Document` can stay `None` on the mediated path.
        || envelope.event == hook::Event::SessionStart
        || (envelope.event == hook::Event::PreTool && !envelope.raw_tool.is_empty());
    // A BYPASSED CALL NOW PAYS THE CONFIG READ, and that invariant is retired
    // deliberately rather than eroded.
    //
    // `BYPASS_ENV`'s own doc said "a bypassed call must never pay a config read",
    // and that was the reason this arm handed `adjudicate` a policy declaring
    // nothing. It cannot survive the protected gate becoming non-bypassable:
    // deciding whether a path is protected requires the `protected` and `[[verb]]`
    // tables, which ARE the config. An empty policy short-circuits `adjudicate` at
    // `policy.is_empty()` before any gate runs, so leaving this arm alone made the
    // narrowing inside `adjudicate` inert — measured, not reasoned: the unit cases
    // over `adjudicate` passed while the compiled binary allowed the write, and
    // `mediated_admission.rs`'s binary-level case is what caught it.
    //
    // THE COST, stated rather than left for a profile to find. A bypassed call
    // pays one config load — the difference between `perf`'s `noop` and `check`
    // arms, ~0.7 ms against a 100 ms budget. `!adjudicable` keeps its old
    // behaviour, because an event with nothing to adjudicate has no protected
    // gate to run either, and that is the arm the hot path actually rides.
    let (policy, waivers) = if adjudicable {
        load_policy(overrides, harness)?
    } else {
        (hook::Policy::declaring_nothing(harness), Vec::new())
    };
    // THE PER-ROW HATCHES (CLOUD-437), resolved here and nowhere earlier.
    //
    // `BYPASS_ENV` is read before the config load above, because a bypassed call
    // must never pay for one. These cannot be: which hatches exist is a property
    // of the loaded rows, so the read has to follow the load. That ordering is
    // the whole reason the general hatch survives as a separate switch rather
    // than becoming just another row's name.
    //
    // Cheap when irrelevant (§4): a ruleset declaring no `bypass_env` — every
    // ruleset until one opts in — collects an empty set, reads no environment,
    // and clones no policy.
    let policy = without_set_hatches(policy);
    // The receipt facts, resolved HERE because `adjudicate` is contractually
    // pure — no I/O, no environment, no clock — and a receipt predicate reads a
    // file and two git refs. Same split the bypass hatch already uses: the
    // boundary looks, the core decides.
    //
    // Resolved only for the names the policy actually requires, so a repository
    // declaring no receipt row does no git work at all on the hottest path in
    // the binary. `None` throughout means "could not look", which allows.
    //
    // A write-triggered row (CLOUD-444) adds one more boundary question before
    // the store is consulted: is the written path one policy judges at all? The
    // exclusions — git-ignored, outside the repository, inside `.git` — are
    // properties of a checkout, so they resolve here and reach `adjudicate` as
    // the same "nothing to answer" absence a failed lookup produces. The
    // `check-ignore` behind it runs only when a write-triggered row actually
    // selected, so a repository declaring none pays nothing for it.
    let required = policy.required_checks_for(&envelope);
    let judgeable = envelope.writes.as_deref().is_none_or(receipt::judgeable);
    // CLOUD-988's declared bounds, resolved beside the checks they qualify.
    let max_ages = policy.max_age_for(&envelope);
    // An AGENT-SOURCED check is resolved from its own record rather than from the
    // receipt store (CLOUD-776), so the two are split before either is read: a
    // repository whose required checks are all agent-sourced must not pay
    // `receipt::verdicts`'s git work for questions it is not asking.
    let (sourced, receipted): (Vec<_>, Vec<_>) = required
        .iter()
        .partition(|(check, _)| policy.agent_fact(check).is_some());
    let receipted: std::collections::BTreeMap<_, _> = receipted
        .into_iter()
        .map(|(check, key)| (check.clone(), *key))
        .collect();
    // Where each agent-sourced record lives on THIS call, resolved once for both
    // readers (CLOUD-859). A record is filed under the subject its receipt row's
    // `key` names, so the boundary resolves that subject here — `adjudicate` may
    // not look, and resolving it per reader would let the two disagree.
    let sourced_store =
        receipt::sourced_store(&sourced, policy.named_receipt_subject(&envelope).as_deref());
    let receipts: hook::ReceiptFacts = receipt_facts(
        &policy,
        &envelope,
        &sourced,
        sourced_store.as_ref(),
        &receipted,
        &Recency {
            max_ages: &max_ages,
            now: instant,
        },
        judgeable,
    );
    let agent_sourced = agent_records(&sourced, sourced_store.as_ref());
    // The key evidence (CLOUD-446), resolved on the same terms and for the same
    // reason: two git queries a pure `adjudicate` cannot make, spent only when a
    // `requires_key` row has already selected this command. A repository
    // declaring none — and a call matching none, which is nearly every call —
    // does no git work here at all.
    // `IsNot` where no `requires_key` row selected this command: the boundary
    // looked and there is no key question. `key_facts` answers the other two.
    let keys: hook::KeyFacts = policy
        .key_base_for(&envelope)
        .map_or(facts::Look::IsNot, key_facts);
    // The waiver facts (CLOUD-610), resolved HERE for exactly the reason above:
    // a waiver lapses on a date, `adjudicate` is contractually pure, and reading
    // the clock inside it would dissolve the contract rather than satisfy it.
    // The boundary already reads a clock for `check`'s tree filter, so this is
    // the one edge where the environment is legible, not a new one.
    //
    // Cheap when irrelevant, the same narrowing `required_checks_for` applies:
    // an empty waiver table skips `today()` entirely, so a repository declaring
    // no waiver pays no clock read on the hottest path in the binary. `today()`
    // can fail — a clock before the epoch — and that propagates rather than
    // defaulting, because a date nobody could read must not silently become a
    // table where every waiver is live.
    let waived = if waivers.is_empty() {
        waiver::Live::new()
    } else {
        waiver::live(&waivers, waiver::today()?)
    };
    // The declared side effects (CLOUD-91), fired BEFORE the decision is written
    // and structurally unable to reach it: `action::fire` returns nothing, so
    // there is no value here to branch on even by mistake.
    //
    // Ordering matters twice. Before `decide`, because `decide` owns stdout and
    // an action's report must not interleave with a decision document a host is
    // parsing. And after the capability check above, which is what makes "a host
    // lacking the capability fires nothing" structural rather than a second
    // check this call site could get wrong.
    fire_actions(&envelope, bypass, overrides, err)?;
    // The end-of-turn facts (CLOUD-85) are NOT resolved, because nothing reads
    // them (CLOUD-906). They used to be, on the stop event only, for `receipts`'
    // reason: `adjudicate` is contractually pure and this reads git and the
    // findings store. That reasoning was right and is now moot.
    //
    // Their one consumer is the policy-input projection's `Fact::Stop` arm — and
    // since CLOUD-889 `adjudicate` returns `Allow` at `Event::Stop` before any
    // rule or module is evaluated, so at Stop the early return precedes the
    // projection, and on every other event this was already the default. The
    // resolved value could not be observed on any path, so every turn paid a git
    // read plus a findings-store read for it.
    //
    // Removed rather than commented as kept-for-later: paying two reads per turn
    // against a consumer that does not exist is speculative, and "kept for a
    // future consumer" is the deferral this repository names a punt. CLOUD-892
    // moves the Stop surface into Rego and gives `Fact::Stop` a reachable
    // consumer; it resolves what it reads, where it reads it. `stop_facts` and
    // its module stay — this drops the call, not the capability.
    let stop = stop::StopFacts::default();
    let prospective = prospective_for(&policy, &envelope);
    // The reading manifest (CLOUD-925), resolved here because the tracked set is
    // a property of a checkout and `adjudicate` is contractually pure.
    //
    // Behind the CLOUD-460 narrowing, and the narrowing is the whole cost story:
    // `manifest_for` asks the row table first, so a repository declaring no
    // `tracked-artifacts` ceiling — which is every repository today — spawns no
    // git and opens nothing. `None` is could-not-look and allows.
    let manifest = manifest_for(&policy, &envelope);
    // The pinned programs (CLOUD-1028), read from the record rather than
    // resolved: asking the pin is `Cost::Effect` and this surface may not spend
    // one. Behind the same narrowing as `prospective_for` — a repository with no
    // mediated module has no consumer for the fact and opens no file.
    let pinned = if policy.reads_pinned(&envelope) {
        pinned::cached(hook_authority_root())
    } else {
        facts::Look::CouldNotLook
    };
    let (tasks, extracted) = session_facts(&policy, &envelope);
    let facts = hook::Facts {
        bypass,
        receipts: &receipts,
        keys: &keys,
        stop: &stop,
        waived: &waived,
        sourced: &agent_sourced,
        prospective: &prospective,
        manifest,
        pinned: &pinned,
        tasks: &tasks,
        extracted: &extracted,
    };
    // THE DOOR (CLOUD-898). Declared handlers run here, under the contract in
    // `crate::handler`: bounded by the parent, fail-open on anything they break,
    // and read rather than forwarded. Their advice joins the one buffer above;
    // their violations join it too, because a handler that broke the contract is
    // something its author must see and nothing else will tell them.
    //
    // AFTER `fire_actions` and BEFORE `decide`, and both halves matter. After,
    // because an action is a side effect that cannot change the answer and a
    // handler can — running the ones that cannot first keeps the ordering a
    // reader would guess. Before, because `decide` owns stdout and a handler's
    // refusal has to reach the same rendering the engine's own does.
    let handled = dispatch_handlers(&envelope, &raw, bypass, overrides, &mut advice)?;
    // THE END-OF-TURN NUDGE (CLOUD-1051), and it is a SEPARATE call from
    // `adjudicate` rather than a widening of it. `adjudicate` returns `Allow` at
    // `Stop` before any rule is read — CLOUD-889's runaway removed by
    // construction — which also meant a `mediated_call` module never ran there,
    // so `stop-posture` was a dead gate for its whole life. `hook::stop_advice`
    // evaluates the modules and answers with TEXT, so there is no value it can
    // return that refuses anything.
    //
    // AT MOST ONE NUDGE PER TURN, and that is the retired shell hook's measured
    // rule rather than a new one: two nudges on one turn is how a channel stops
    // being read. A turn already handed a handler's advice has been told
    // something more specific, so the module's line is appended only to a silent
    // buffer.
    fill_turn_advice(&policy, &envelope, &facts, overrides, &mut advice);
    // THE DECISION IS RESOLVED BEFORE THE ADVISORY IS SPOKEN (CLOUD-1175), and
    // that ordering is the whole fix rather than a tidy-up.
    //
    // These two writes share one stream. `emit_advisory` puts a JSON document on
    // `out` and `render` puts the decision document on `out` a few lines later,
    // so a call that is BOTH advised and denied emitted two — advisory first.
    // `encode_advice`'s own header states what that costs: the channel "is one
    // document per call on every host that has one, so two emits on the same
    // batch would put two JSON documents on stdout and the host would read the
    // first and discard the rest". Claude Code carries a mediated refusal IN
    // BAND with exit 0, so the discarded document is the refusal and nothing in
    // the exit status refuses either.
    //
    // Measured on `8e4c4f1`: one `Edit` to a governed shell path from a branch
    // with a stale claim receipt — `shell-write-advisory` advises,
    // `claim-needs-receipt` denies — put 2 documents on stdout and exited 0.
    //
    // It was unreachable until `PreToolUse` entered Claude Code's `delivered_on`
    // in that same commit: before it, `encode_advice` answered `None` here and
    // the advice went to the operator's stream. The other three delivering
    // events carry no verdict, so none of them can collide.
    let decision = admit_mediated(compose(handled, &policy, &envelope, &facts), out)?;
    // A REFUSAL OUTRANKS ADVICE ABOUT THE SAME CALL, which is this function's own
    // rule rather than a new one: the nudge block above keeps a module's line out
    // of a buffer a handler already filled because that turn "has been told
    // something more specific", and `an_engine_deny_beats_a_handler_grant_on_the
    // _same_call` drops a handler's grant beside a deny because printing both
    // "reads as a disagreement the reader has to arbitrate when the arbitration
    // has already happened". A refusal is strictly more specific than advice
    // about the call it refuses.
    //
    // `Ask` is included for the same reason: it is a verdict document too, and
    // the escalation is what the reader must answer.
    //
    // The `Allow` path is untouched — advice is the only document there, which is
    // the behaviour CLOUD-1131 measured and shipped. Suppressing advice generally
    // would trade a dropped deny for a dropped advisory.
    let ceiling = policy.advisory.as_ref();
    emit_channel(harness, &envelope, out, err, advice, ceiling, &decision)?;
    let hatch = hatch_for(&policy, &decision);
    let rendering = Rendering {
        hatch: &hatch,
        ceiling: policy.refusal.as_ref(),
    };
    render(harness, &envelope, decision, &rendering, mode, out, err)
}

/// The hatch a refusal advertises, by name.
///
/// RESOLVED HERE RATHER THAN INSIDE [`render`], because `render` deliberately
/// cannot see the policy (CLOUD-898) and that property is worth more than the
/// convenience: a renderer that cannot see the inputs cannot re-decide by
/// accident. A hatch NAME is not such an input — it is a string the renderer
/// prints and never branches on — so handing it over costs nothing.
///
/// Its own function rather than a block in the caller, because the caller reached
/// `clippy::too_many_lines` and a length limit is answered by moving a nameable
/// step out, never by widening the limit.
fn hatch_for(policy: &hook::Policy, decision: &hook::Decision) -> String {
    match decision {
        hook::Decision::Deny(refusal) | hook::Decision::Ask(refusal) => {
            policy.bypass_env_for(refusal.rule()).to_owned()
        }
        // Nothing is being refused, so nothing advertises a hatch. The general
        // name stands in rather than an empty string: the value is unread on
        // these arms, and a blank one would render as `Bypass with =1.` if a
        // later arm ever did read it.
        _ => hook::BYPASS_ENV.to_owned(),
    }
}

/// Turn a mediated refusal into an allow when a spent admission covers it.
///
/// The mediated-surface twin of [`filter_admitted`], which has done this for tree
/// findings since CLOUD-1120. Both bind the same five fields through
/// [`admission::admitted`], so an admission cannot be harvested across gates,
/// classes, subjects, trees or policy generations.
///
/// # Why a mediated refusal was inadmissible until now
///
/// Not a decision — a gap. `adjudicate` is pure by contract, so the deny site
/// cannot read a store; and `Refusal` carried no subject, so even at the boundary
/// there was nothing to bind. The consequence was that `path write refused` —
/// the class most in need of an audited way through, because the surface it names
/// as the remedy IS the file it refuses — had only the bare environment variable.
/// This repository already ruled that shape out for `issue file same`: *the
/// point of the admission mechanism is that the bare variable stops working*.
///
/// # What it will not do
///
/// **A class declaring no override route is untouched.** The lookup binds the
/// class token, and `admission::questions_for` returns `None` without an override
/// route, so no admission for such a class can exist to be found. That keeps
/// `verdict::validate`'s two directions composing exactly as they did: a class
/// either offers a real way out and may additionally be overridden, or it offers a
/// real way out and may not.
///
/// **`Ask` is not filtered.** An escalation is a question put to a person, and a
/// record the asker wrote themselves is not an answer to it.
///
/// # Errors
///
/// Propagates only a store-resolution failure. An unreadable store, an
/// unparseable record and an absent directory are all "no admission" inside
/// [`admission::admitted`] — the fail-closed direction for a suppression.
fn admit_mediated(decision: hook::Decision, out: &mut dyn Write) -> Result<hook::Decision> {
    let hook::Decision::Deny(refusal) = &decision else {
        return Ok(decision);
    };
    let (Some(class), Some(subject)) = (refusal.verdict(), refusal.subject()) else {
        return Ok(decision);
    };
    let root = hook_authority_root();
    let Ok(head) = git::head_commit(root) else {
        return Ok(decision);
    };
    let Ok((epoch, _)) = epoch::describe(root, None) else {
        return Ok(decision);
    };
    let Some(address) = admission::admitted(root, refusal.rule(), class, subject, &head, &epoch)?
    else {
        return Ok(decision);
    };
    // POINTER, NEVER THE ANSWERS (rule 4), and the same line `filter_admitted`
    // emits: the address and the class are what a reader needs to find the record;
    // the reasoning the author typed stays in the store where they wrote it.
    // Saying WHICH record admitted the call is what stops this being the silent
    // bypass again, wearing a record's clothes.
    writeln!(out, "batten: {class} admitted by {address} — {subject}")?;
    Ok(hook::Decision::Allow)
}

/// The two producers that ride the DECISION rather than a batch boundary.
///
/// Split out of `run_hook` for `collect_batch_advice`'s reason and one more: that
/// function is the hottest in the binary and sits under a line lint, so a third
/// producer belongs beside the second rather than inline. The ordering is the
/// ordering below, and each block carries its own argument.
fn fill_turn_advice(
    policy: &hook::Policy,
    envelope: &hook::Envelope,
    facts: &hook::Facts<'_>,
    overrides: &Overrides,
    advice: &mut Vec<advisory::Advice>,
) {
    if advice.is_empty()
        && let Some(nudge) =
            hook::stop_advice(policy, envelope, facts).or_else(|| stop_nudges(overrides, envelope))
    {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Caution,
            nudge,
        ));
    }
    // THE WRITE-TIME SIGNAL (CLOUD-1131), and it is the delivery half of the
    // demotion `hook::policy_rules` performs. A `mediated_call` module enabled at
    // `severity = "warn"` no longer denies; without this line its violation would
    // reach nobody at all, which is a worse answer than the deny it replaced —
    // an advisory nothing surfaces is a sensor with no reader.
    //
    // NOT FOLDED INTO THE `advice.is_empty()` BLOCK ABOVE. That one is the
    // end-of-turn channel, where at most one nudge per turn is the measured rule
    // because two nudges is how a channel stops being read. This one rides a
    // single tool call the agent is making right now: it is about the call in
    // hand rather than about the turn, and suppressing it because something else
    // already spoke would make the signal arrive at some calls and not others for
    // reasons the reader cannot see. At `Stop` the two producers render the same
    // violation through the same function, so the equality test is what keeps one
    // finding from arriving twice rather than a second rule about which one wins.
    if let Some(signal) = hook::policy_advice(policy, envelope, facts)
        && !advice.iter().any(|entry| entry.text == signal)
    {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Warning,
            signal,
        ));
    }
}

/// Reconcile what a handler said with what the engine decides.
///
/// **A handler's refusal REPLACES the engine's decision; a handler's grant may
/// only UPGRADE an allow.** Both halves are enforced here rather than promised,
/// and the asymmetry is the whole safety property of the pre-approval channel: a
/// `Deny` from either side is a stop, so a dispatched program refusing is at worst
/// redundant — while a grant that could replace a decision would let a dispatched
/// program spend a refusal the engine's own rows reached.
///
/// [`hook::Decision::Waived`] is deliberately not upgraded either. A waived deny
/// is a refusal that was let through and owes a record; telling the host not to
/// prompt about it would suppress the one trace the waiver table exists to leave.
///
/// This is the second of the pre-approval's two bounds, and the split is what
/// keeps either from being a comment: [`dispatch_handlers`] enforces that a
/// refusal outranks a grant *among handlers*, because only it sees them all, and
/// this enforces that the engine outranks both, because only this has the
/// engine's answer.
///
/// `adjudicate` is called at most once on every path, which is also why this is a
/// function rather than an expression at the call site: the pre-approval arm needs
/// the engine's decision to decide whether to keep the grant, and a reader has to
/// be able to see that it is not consulted twice.
fn compose(
    handled: Option<hook::Decision>,
    policy: &hook::Policy,
    envelope: &hook::Envelope,
    facts: &hook::Facts<'_>,
) -> hook::Decision {
    match handled {
        Some(hook::Decision::Preapproved(reason)) => {
            match hook::adjudicate(policy, envelope, facts) {
                hook::Decision::Allow => hook::Decision::Preapproved(reason),
                // The engine decided something, so the grant is dropped — silently.
                // It carries no finding, and reporting "a handler wanted to allow
                // this" beside a refusal would read as a disagreement the reader has
                // to arbitrate when the arbitration has already happened.
                decided => decided,
            }
        }
        Some(forced) => forced,
        None => hook::adjudicate(policy, envelope, facts),
    }
}

/// Fill the advisory buffer from the two producers that ride a batch boundary.
///
/// Split out of `run_hook` so the batch-boundary question lives in one place —
/// and because `run_hook` is the hottest function in the binary and every line
/// in it is read by somebody diagnosing a mediated call.
///
/// Which event IS the boundary is the capability table's answer rather than a
/// literal here (CLOUD-389): `degrade` hands back `PostToolBatch` where the host
/// emits it and `PostTool` where it does not, so asking through the table is
/// what keeps the rule in one place. A second `||` here would be a copy of that
/// table that could disagree with it.
fn collect_batch_advice(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
    advice: &mut Vec<advisory::Advice>,
) -> Result<()> {
    if Some(envelope.event) == harness.capabilities().degrade(hook::Event::PostToolBatch) {
        drain_advisories(envelope, overrides, mode, err, advice)?;
    }
    report_contract_drift(envelope, overrides, advice);
    // ORDER IS LOAD-BEARING: `refresh_pinned` rebuilds the record the health
    // report then reads, so a session whose pin record went stale between
    // sessions reports the repaired state rather than the state it started in.
    refresh_pinned(envelope, overrides);
    // EXPIRY BEFORE REPAIR, and the order is the whole of the race argument
    // `expire_wiring_record` used to give for the repair living elsewhere: in one
    // process, in this order, the record describing what this session LOADED is
    // dropped before a repair can write one describing what it FIXED.
    expire_wiring_record(envelope);
    repair_startup_rows(envelope, overrides);
    report_container_health(envelope, overrides, advice);
    Ok(())
}

/// Record what the pin provides, once per session (CLOUD-1028).
///
/// **Here because this is where an effect is admissible.** Asking the pin runs a
/// program, which the fact model bars from the mediated path — so the spawn
/// happens on the one event that is not a call being adjudicated, and every
/// mediated call afterwards reads the record instead.
///
/// `SessionStart` only, and `PostToolBatch` deliberately not: a per-batch spawn
/// buys news that a per-session one already has, since the record is keyed to the
/// pin's own configuration rather than to a clock. The cost of that choice is
/// stated rather than hidden — a tool installed MID-session moves the key, so the
/// next read misses and the fact reads could-not-look until the following session
/// start. Could-not-look allows, so the failure mode is a quiet gate rather than
/// a false refusal, which is the direction this fact must always fail in: it
/// names every program in the project.
///
/// Fails open on everything, and returns nothing there is to branch on: a
/// session whose pin cannot be reached is a session where this fact answers
/// could-not-look, which is exactly what an absent record already says.
fn refresh_pinned(envelope: &hook::Envelope, overrides: &Overrides) {
    if envelope.event != hook::Event::SessionStart {
        return;
    }
    let here = hook_authority_root();
    // Narrowed to a repository that has a consumer, read the same way
    // `report_contract_drift` reads its own declaration: a config this reporter
    // cannot resolve is one where the fact answers could-not-look anyway, so
    // every arm here returns rather than erroring on an event nothing is meant
    // to be blocked at.
    let Ok(resolved) = resolve::resolve(here, overrides) else {
        return;
    };
    if !resolved
        .rules
        .iter()
        .any(|rule| rule.kind == rules::RuleKind::Policy)
    {
        return;
    }
    let _refreshed = pinned::refresh(here);
}

/// Run this repository's declared `[[startup]]` repairs, once per session
/// (CLOUD-1324).
///
/// # Repair rather than refusal, and the measurement behind that
///
/// A launcher that re-provisions its own hook registrations does it on its own
/// schedule: observed here rewriting two surfaces at 03:49 that were emptied at
/// 01:08, mid-session. A gate keyed on the count is therefore red at
/// unpredictable moments and blocks work that has nothing to do with it — which
/// is exactly what `[hook] exclusive = true` did to this repository before it was
/// withdrawn. A repair has no such failure mode: it runs at the one moment the
/// environment is about to be used, and a later drift is repaired at the next
/// session start instead of refusing a commit in the middle of this one.
///
/// # Why no flag is needed here, and one is needed on the verb
///
/// `batten startup --repair` makes a person say what they are asking for.
/// Nothing asks here, because the consumer already did: **a `repair` written in
/// the committed authority IS the authorisation to run it.** A row with no
/// `repair` is untouched, which is how a consumer declares a precondition it
/// wants reported and not acted on.
///
/// Rewriting anything under a person's `$HOME` therefore requires a row saying
/// so. That is non-negotiable rule 1's posture one layer up: which repairs a
/// container needs is the project's statement, never the engine's.
///
/// # Never a verdict, and silent on every failure
///
/// `SessionStart` is not a call being adjudicated. What is still wrong after the
/// repairs is reported by [`report_container_health`], which runs next; nothing
/// here can refuse a session, because a session refused over its own environment
/// is one that cannot run the repair the report names.
fn repair_startup_rows(envelope: &hook::Envelope, overrides: &Overrides) {
    if envelope.event != hook::Event::SessionStart {
        return;
    }
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return;
    }
    let Ok(resolved) = resolve::resolve(here, overrides) else {
        return;
    };
    // Discarded deliberately: what the repairs found is `report_container_health`'s
    // to say, off a fresh reading. Reporting it from here would describe a state
    // that the very next call re-decides.
    let _outcomes = startup::repair(here, &resolved.startup);
}

/// Say at session start whether this container is misconfigured (CLOUD-1324).
///
/// # Why the report is pushed rather than waited for
///
/// `batten doctor` already answers this, and answering it is not the problem:
/// **nobody runs it.** A container that is missing a program, wired to hooks the
/// tree does not declare, or carrying a pin record that stopped validating looks
/// exactly like a healthy one until some gate silently decides nothing — which is
/// the failure this whole file exists to refuse, one level up. The session's
/// first moment is the only point where the news is still cheap: everything after
/// it is work done on an unknown machine.
///
/// So the diagnosis rides the advisory channel at `SessionStart`, and the agent
/// learns what is broken before it has spent anything on it.
///
/// # Silent on a healthy container, which is what keeps it credible
///
/// Every check passing emits nothing. An advisory that speaks every session is
/// one every reader learns to scroll past, and the drift notice above already
/// pays for that lesson.
///
/// # Pointer-only (non-negotiable rule 4)
///
/// [`doctor::Check::line`] is the §6 rendering — a check name, a verdict token,
/// and the consumer's own declared subjects. No path off the disk, no file
/// contents, no host identity. It is the same bytes `batten doctor` prints, from
/// the same producer, so the advisory and the verb cannot disagree.
///
/// # Never a verdict
///
/// A `Warning`, not a refusal. `SessionStart` is not a call being adjudicated,
/// and a broken container is a provisioning failure rather than a policy one —
/// refusing the session would leave the reader unable to run the very repair the
/// advisory names.
fn report_container_health(
    envelope: &hook::Envelope,
    overrides: &Overrides,
    advice: &mut Vec<advisory::Advice>,
) {
    if envelope.event != hook::Event::SessionStart {
        return;
    }
    let here = hook_authority_root();
    // A tree with no consumer has nothing to be misconfigured FOR, which is
    // `refresh_pinned`'s narrowing and for the same reason.
    if !here.join(config::CONFIG_FILE).exists() {
        return;
    }
    let report = doctor::diagnose(here);
    // THE CONSUMER'S OWN ROWS, RE-DECIDED AFTER THE REPAIRS RAN. `evaluate`
    // rather than `repair`: `repair_startup_rows` already had its turn, and a
    // second repair pass here would report the state of a third one. What is
    // left is what a reader actually has to deal with.
    let rows = resolve::resolve(here, overrides)
        .map(|resolved| startup::evaluate(here, &resolved.startup))
        .unwrap_or_default();
    let failing: Vec<String> = report
        .checks
        .iter()
        .filter(|check| !check.ok)
        .map(doctor::Check::line)
        .chain(
            rows.iter()
                .filter(|outcome| !outcome.ok)
                .map(startup::Outcome::line),
        )
        .collect();
    if failing.is_empty() {
        return;
    }
    let mut out = String::from(
        "container-health: this session's environment does not match what the tree declares\n\n",
    );
    for line in &failing {
        out.push_str("  ");
        out.push_str(line);
        out.push('\n');
    }
    out.push_str(
        "\n`batten doctor` reports the engine's own checks and `batten startup` this\n\
         repository's declared `[[startup]]` rows; `-J` is the data channel for both. Each\n\
         line above names what failed and the subjects it failed over, and a row's meaning\n\
         is its `gloss` in `batten.toml`.\n\n\
         A gate whose program cannot be reached decides NOTHING while the config reads as\n\
         if it does, so treat this as work before the work rather than as background noise.\n\
         Every declared repair has already run this session; what is listed is what it did\n\
         not fix. `batten startup --repair` runs them again by hand.\n\n\
         Reported at session start only, and only when something is wrong.\n",
    );
    advice.push(advisory::Advice::new(severity::AdvisoryTier::Warning, out));
}

/// Drop the at-load wiring record at the one moment it stops being true
/// (CLOUD-893).
///
/// A host reads its hook wiring when a session starts, so at `SessionStart` — and
/// only there — the disk and what the harness has loaded are the same thing by
/// definition. That makes this the one honest place to expire the record
/// `batten wiring reclaim` leaves behind, and it needs no session identity to do
/// it: the event IS the identity.
///
/// **The clear has exactly one writer, and the repair is now sequenced against
/// it rather than kept away from it** (CLOUD-1324). This comment used to read
/// *"running the reclaim from a session-start handler would put a write and this
/// clear inside one unordered batch, and whichever landed second would decide
/// between the honest red and the false green the record exists to refuse"* —
/// which is a correct argument about an unordered batch of independent handlers
/// and not one about [`collect_batch_advice`], where the order is written down
/// in one process. Expiry first, then [`reclaim_wiring`]: the record this session
/// loaded under is gone before a repair can write one describing the repair.
///
/// Silent on every failure, and never a verdict. A session-start hook that
/// refused a session over a stale bookkeeping file would be a gate on the wrong
/// object; a record that outlives its session costs one extra red run of the
/// consumer's gate, which names the remedy anyway.
fn expire_wiring_record(envelope: &hook::Envelope) {
    if envelope.event != hook::Event::SessionStart {
        return;
    }
    let _ = wiring::clear_at_load(hook_authority_root());
    // AND THE CLASSES THIS SESSION HAS ALREADY BEEN TOLD (CLOUD-1386), on the
    // same event and for the same reason: the event is the session identity, and
    // a sighting that outlived its session would withhold a remedy from a reader
    // who has never seen it. Clearing costs a directory removal; not clearing
    // costs the exact defect the store exists to prevent.
    refusal::forget_sightings(hook_authority_root());
}

/// Run the declared handlers for this envelope's event (CLOUD-898).
///
/// Returns the decision a handler forced, if any, and appends its advice and its
/// contract violations to `advice`. A handler that refuses becomes a
/// [`hook::Decision::Deny`] rendered by `decide`, so a handler's refusal and the
/// engine's own travel the identical per-host channel — the point of the door
/// being that a dispatched program cannot invent a second one.
fn dispatch_handlers(
    envelope: &hook::Envelope,
    raw: &str,
    bypass: bool,
    overrides: &Overrides,
    advice: &mut Vec<advisory::Advice>,
) -> Result<Option<hook::Decision>> {
    if bypass {
        return Ok(None);
    }
    // `fire_actions`' reading, for `fire_actions`' reason: a handler table is a
    // per-repository declaration, so it comes from the REPOSITORY's authority
    // rather than the cwd's (CLOUD-824).
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(None);
    }
    let Some(hook_config) = resolve::resolve(here, overrides)?.hook else {
        return Ok(None);
    };
    // CLOUD-460's narrowing, and the reason `pre-tool` is affordable at all: a
    // repository declaring no handler for this event pays one slice scan and
    // never reaches a spawn.
    if !handler::selects(&hook_config.handlers, envelope.event, &envelope.raw_tool) {
        return Ok(None);
    }
    let dispatched = handler::dispatch(
        &hook_config.handlers,
        envelope.event,
        &envelope.raw_tool,
        raw,
    );
    // TIERED AT THE PUSH SITE (CLOUD-896), because "how soon must this be
    // answered" is a property of what is being said and the boundary has only
    // the string. A handler's advice is `Advisory`; a contract violation is
    // `Warning`, because it is a statement that a declared invariant is broken.
    advice.extend(
        dispatched
            .advice()
            .into_iter()
            .map(|text| advisory::Advice::new(severity::AdvisoryTier::Advisory, text)),
    );
    advice.extend(
        dispatched
            .violations()
            .into_iter()
            .map(|text| advisory::Advice::new(severity::AdvisoryTier::Warning, text)),
    );
    // A REFUSAL IS DEMOTED TO ADVICE ON A MOMENT THAT CANNOT CARRY ONE, and this
    // is the door's own loophole rather than a hypothetical. CLOUD-889 made
    // `adjudicate` structurally unable to refuse at `Stop` — that is what ended
    // the runaway this branch is named after — and `run_hook` reads
    // `handled.unwrap_or_else(|| adjudicate(..))`, so a handler's `Deny` REPLACES
    // that decision instead of being reconciled with it. A `[[hook.handler]]
    // on = "stop"` exiting 2 would therefore refuse every turn, unbounded by
    // `stop_active`, through the exact path the branch opened. The same hole runs
    // one event wider: `session-start`, `config-change` and `task-completed` all
    // return `Allow` before any rule is read, for their own stated reasons.
    //
    // So the handler still RUNS on those events and still speaks — its reason
    // becomes advice, which is the channel those moments do have — and what it
    // cannot do is convert that into a verdict the engine itself declines to
    // reach. `Event::carries_a_verdict` is the one authority both producers ask,
    // so this cannot drift from `adjudicate`'s arms.
    let Some((id, reason)) = dispatched.refusal() else {
        // NO REFUSAL, SO A GRANT MAY BE CONSIDERED — and only in that order. A
        // refusal outranks a pre-approval absolutely: two handlers disagreeing
        // about one call resolve toward the refusal, because a grant that could
        // overrule one would let a dispatched program spend a verdict another
        // dispatched program reached.
        //
        // Returned as a `Preapproved` for the CALLER to reconcile with the
        // engine's own decision, never as a decision in itself. That second bound
        // — a grant may only upgrade an `Allow` — is `run_hook`'s, because only
        // `run_hook` has the engine's answer in hand. Splitting the two bounds
        // across the two functions that can each enforce one is what keeps either
        // from being a comment.
        if let Some((id, reason)) = dispatched.preapproval() {
            return Ok(Some(hook::Decision::Preapproved(format!(
                "hook.handler.{id}: {reason}"
            ))));
        }
        return Ok(None);
    };
    if !envelope.event.carries_a_verdict() {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Caution,
            format!("hook.handler.{id}: {reason}"),
        ));
        return Ok(None);
    }
    Ok(Some(hook::Decision::Deny(
        crate::refusal::Refusal::declared(
            format!("hook.handler.{id}"),
            verdict::Native::HandlerDenied,
            // THE HANDLER'S OWN WORDS TRAVEL AS A SUBJECT, not as the reason
            // (CLOUD-1050). The class is Batten's — "a configured hook handler denied
            // the call" — and the handler's text is what it denied over, which is a
            // subject of that class rather than a competing statement of it. Keeping
            // it in the `reason` slot would have made a class Batten declares
            // indistinguishable from free text a third party wrote.
            &[verdict::Subject::Artifact {
                artifact: reason.to_owned(),
            }],
            // A handler's reason may or may not name a remedy, so the fix falls back
            // to the class's declared route rather than being invented here. §5's
            // "every refusal names something to run" is now the REGISTRY's obligation
            // and `verdict::validate` refuses a class that fails it.
            crate::refusal::Fix::None,
        ),
    )))
}

/// Assemble a `requires_key` row's checkout evidence (CLOUD-446).
///
/// Two queries, and every failure among them reads as **could not look** — which
/// allows. That is the fail-open posture the bash guard it ports had at each of
/// the same points (`|| exit 0`), and it is the right one for a hook: refusing
/// because there is no checkout would make Batten the reason a call cannot run,
/// in exactly the directories it governs nothing.
///
/// A detached HEAD is not a failure, only a missing *source*: the commit
/// messages still answer, so the evidence is the shorter list rather than
/// `None`. `base` failing to resolve is a failure, because with no range there
/// is no commit evidence at all and the branch name alone would be a narrowing
/// nobody wrote.
///
/// **A shallow clone is the same failure, and it is the one that was measured.**
/// Truncated history means the range holds a suffix of the work rather than the
/// work, so "no commit names a key" is a statement about what was fetched. CI
/// takes its base with `git fetch --depth=1` and its head at the same depth, and
/// the first version of this refused every PR there — a gate that fired on the
/// one checkout its predicate cannot be evaluated in. It is checked before the
/// range is read rather than after, because a truncated range answers
/// confidently and wrongly.
/// What the agent reported for each agent-sourced check (CLOUD-776, CLOUD-834).
///
/// **The records themselves, kept rather than discarded once the receipt-side
/// verdict is derived.** A `Validity` answers "is this check satisfied"; the
/// record answers "what did the agent run, and what did it find". `facts.rs`
/// gives those two questions two variants, so the policy input carries them
/// under two keys — folding one into the other would leave
/// [`facts::Fact::AgentSourced`] with no spelling of its own, which is the
/// "exactly one key" property CLOUD-834 asserts.
///
/// Same narrowing as every other fact on this path: `checks` is empty unless a
/// required check is agent-sourced, so a repository declaring none pays nothing
/// and the answer is `None` rather than an empty map.
fn agent_records(
    checks: &[(&String, &rules::ReceiptKey)],
    store: Option<&receipt::SourcedStore>,
) -> hook::AgentFacts {
    if checks.is_empty() {
        return None;
    }
    // A store that could not be built answers `None` for the same reason an
    // empty `checks` does: there is nothing this boundary looked at, so the
    // policy input carries no records rather than an empty map asserting there
    // are none.
    let store = store?;
    let mut records = std::collections::BTreeMap::new();
    for (check, _) in checks {
        if let Some(record) = store.record(check) {
            records.insert((*check).clone(), record);
        }
    }
    Some(records)
}

/// The checkout evidence behind a `requires_key` row, or the reason there is none.
///
/// Every early return here is [`facts::Look::CouldNotLook`] and each is the same
/// kind of failure: no checkout, a shallow clone whose history is not there to
/// read, or a `base` git cannot resolve. None of them is "looked and found no
/// key" — that answer belongs to the caller, which knows whether any row asked
/// (CLOUD-787).
fn key_facts(base: &str) -> hook::KeyFacts {
    let inner = || -> Option<Vec<String>> {
        let repo = git::repo_root(Path::new(".")).ok()?;
        if git::is_shallow(&repo).ok()? {
            return None;
        }
        let messages = git::log_messages(&repo, base).ok()??;
        let mut evidence = vec![messages];
        evidence.extend(git::current_branch(&repo).ok().flatten());
        Some(evidence)
    };
    inner().map_or(facts::Look::CouldNotLook, facts::Look::Is)
}

/// Assemble the end-of-turn gate's inputs (CLOUD-85).
///
/// **Outside a repository, both inputs are absent rather than clean.** `batten
/// hook` is registered once and then mediates every turn in whatever directory
/// the agent is in; answering "nothing is at risk" for a directory Batten does
/// not govern would be a claim nobody made, and answering "deny" would make the
/// guard the reason a turn cannot end.
///
/// **Uncalled today, and kept rather than deleted** (CLOUD-906). `run_hook`
/// stopped resolving these because nothing could observe the result; what stays
/// here is the semantics above, which is the part worth keeping and the part a
/// rewrite would get wrong. CLOUD-892 gives `Fact::Stop` a reachable consumer
/// and is where the call comes back.
///
/// `#[expect]` rather than `#[allow]` for the spawn census's reason: the day a
/// caller returns, this annotation is unfulfilled and goes red, so the licence
/// is deleted by whoever restores the call instead of outliving it.
#[expect(
    dead_code,
    reason = "CLOUD-906: the only consumer is unreachable until CLOUD-892 moves the Stop surface into Rego; the semantics are what is being kept"
)]
fn stop_facts(overrides: &Overrides) -> Result<stop::StopFacts> {
    let here = Path::new(".");
    let Ok(repo) = git::repo_root(here) else {
        return Ok(stop::StopFacts::default());
    };
    // Config is optional here, unlike for the mediated-call policy: the at-risk
    // half is a property of the checkout and answers with or without a
    // `batten.toml`, and the config-supplied target simply goes unset.
    let target = if here.join(config::CONFIG_FILE).exists() {
        resolve::resolve(here, overrides)?.must_land_on.clone()
    } else {
        None
    };
    // A store this checkout is not bound to yields no denials — an answer, not a
    // gap. `resolve` reads and never writes, which is what keeps the stop gate's
    // `read` effect honest.
    let store_dir = store::bound_dir(&store::resolve(&repo)?);
    stop::facts(Some(&repo), target.as_deref(), store_dir.as_deref())
}

/// Spawn the `[[hook.action]]` rows declared for this envelope's event.
///
/// Reads config on its **own** path rather than reusing [`load_policy`]'s
/// result, because the two answer different questions: the policy is the
/// mediated-call rule set and is deliberately not loaded for a bypassed or
/// nothing-to-judge call, while the action table is keyed on the event alone.
///
/// The hot path is preserved all the same, and structurally: `action::validate`
/// refuses an action on `pre-tool`, so this returns before touching config for
/// the one event that runs on every mediated tool call.
///
/// A bypassed run fires nothing. `BATTEN_HOOK_BYPASS` means "do not mediate this
/// call", and spawning the operator's cleanup command while claiming not to be
/// mediating would be the surprising reading.
fn fire_actions(
    envelope: &hook::Envelope,
    bypass: bool,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<()> {
    if bypass || envelope.event == hook::Event::PreTool {
        return Ok(());
    }
    // The REPOSITORY's authority, not the cwd's (CLOUD-824). Same reading as
    // `load_policy` below and for the same reason: an action table is a
    // per-repository declaration, and reading it from a linked worktree's
    // checkout would fire a different set depending on which ref that worktree
    // sits on. Resolved after the two refusals above, so a bypassed or pre-tool
    // call still pays nothing.
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(());
    }
    let Some(hook_config) = resolve::resolve(here, overrides)?.hook else {
        return Ok(());
    };
    action::fire(
        &hook_config.actions,
        envelope.event,
        action::Facts {
            event: envelope.event.as_str(),
            tool: &envelope.raw_tool,
            path: envelope.writes.as_deref().unwrap_or_default(),
            session: envelope.session.as_deref().unwrap_or_default(),
        },
        err,
    );
    Ok(())
}

/// Wake the advisory drain for this batch boundary (CLOUD-79).
///
/// **Every early return here is a decision, not an omission.** This runs on every
/// post-tool event of every session on every host, most of them in directories
/// that are not Batten repositories, so the ladder of refusals below is ordered
/// cheapest-first (§4) and each one is the honest reading of its condition:
///
/// * not a repository, or no committed authority → the drain has no policy to
///   pace itself from and no store to read;
/// * no bound store → nothing has ever been recorded here, so there is nothing
///   to drain. An unbound store is an ordinary first-run state, not an error;
/// * no session id → the host reported none, so there is no key under which a
///   window could be remembered. CLOUD-43's contract is that a missing session
///   degrades to **per-invocation** handling, and per-invocation is precisely
///   the once-per-verifier behaviour a coalescing window exists to prevent — so
///   the honest degradation is to hold the wake rather than to drain on each
///   one. It is reported on the verbose rung, because on a host that never sends
///   a session this is the ordinary state rather than news.
///
/// A drain failure is **fail-loud and never a deny**: the error propagates to the
/// binary boundary as an ordinary failure, where §7 spends `1`/`3`, neither of
/// which any host reads as a refusal.
/// Put one advisory in front of the model, on whichever channel this host
/// actually delivers (CLOUD-461).
///
/// **The choice is the capability table's, asked about this event's host
/// spelling**, so no caller reconstructs it from a harness name. `Some` body
/// means the host reads an in-band document on exit 0 and the advisory goes to
/// **stdout**; `None` means it declares no such channel and the text stays on
/// stderr, where it is the operator's rather than the model's.
///
/// **Never a verdict, on either branch.** [`hook::encode_advice`] emits an
/// object with no `permissionDecision` field, the exit code is untouched, and
/// this runs only at a boundary where `adjudicate` has already returned
/// `Allow` — so stdout carries at most one document per invocation and none of
/// them can refuse a call. An advisory surface that could block would be a gate
/// (house-style §0.3), and `drain.rs` states that as its own contract.
/// Admit this call's advice to one emission, under the channel's own ceiling
/// (CLOUD-896).
///
/// **The whole set is only in hand here**, which is why the ceiling is applied at
/// this point and not at any producer: `[drain] token_budget` bounds ONE
/// producer, and N producers under N budgets is a channel whose real ceiling is
/// whatever the set happens to sum to.
///
/// **A refusal outranks advice about the same call**, which is why the decision
/// reaches here rather than a boolean the caller derived: `Ask` is a verdict
/// document too, and the escalation is what the reader must answer. The `Allow`
/// path is untouched — advice is the only document there, which is the behaviour
/// CLOUD-1131 measured and shipped.
fn emit_channel(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    out: &mut dyn Write,
    err: &mut dyn Write,
    advice: Vec<advisory::Advice>,
    ceiling: Option<&advisory::Channel>,
    decision: &hook::Decision,
) -> Result<()> {
    let speaks_a_verdict = matches!(decision, hook::Decision::Deny(_) | hook::Decision::Ask(_));
    if advice.is_empty() || speaks_a_verdict {
        return Ok(());
    }
    let emission = advisory::admit(advice, ceiling);
    emit_advisory(harness, envelope, out, err, &emission.text)
}

fn emit_advisory(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    out: &mut dyn Write,
    err: &mut dyn Write,
    text: &str,
) -> Result<()> {
    match hook::encode_advice(harness, &envelope.raw_event, text)? {
        Some(body) => {
            writeln!(out, "{body}")?;
        }
        // No reachable channel: silence toward the model, and the text stays on
        // the operator's stream. Not a deny and not an error — an advisory that
        // degraded to either would invent a verdict nobody wrote, which is the
        // mirror of the inversion `encode_ask` refuses.
        None => output::verdict(err, text)?,
    }
    Ok(())
}

/// Tell this session what moved under it, once per change-set (CLOUD-461).
///
/// Fails **open** on everything it cannot establish — not a repository, no
/// committed authority, no `[contract]` table, an unreadable snapshot — because
/// the cost of a missed notice is one reminder and the cost of a refusing
/// reporter is a blocked call at a moment nothing is meant to be blocked at.
///
/// The write happens **before** the emit and is the rate limit itself, the same
/// shape `Decision::Waived`'s audit line has: `adjudicate` is pure and owns no
/// channel, so the boundary both speaks and records, and the two cannot disagree
/// about whether a notice was spent. Recording first is the direction that fails
/// safe — a snapshot written for a notice nobody read costs one missed reminder,
/// where a notice read but unrecorded costs an unbounded repeat of it.
fn report_contract_drift(
    envelope: &hook::Envelope,
    overrides: &Overrides,
    advice: &mut Vec<advisory::Advice>,
) {
    // The two events that carry the predicate, tested HERE rather than at the
    // call site so the function owns which moments it serves.
    //
    // `SessionStart` is load-bearing rather than merely convenient: an
    // autonomous session's first batch is routinely fetch-and-rebase, so a
    // snapshot seeded at the END of that batch would record post-rebase state
    // and the session would never learn what moved under it.
    //
    // Both are events no host offers a deny channel for, which is what makes
    // this structurally unable to become part of adjudication.
    if !matches!(
        envelope.event,
        hook::Event::PostToolBatch | hook::Event::SessionStart
    ) {
        return;
    }
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return;
    }
    let Ok(repo) = git::repo_root(here) else {
        return;
    };
    let Ok(git_dir) = git::git_dir(&repo) else {
        return;
    };
    // Fail open, per the contract above: an authority this reporter cannot read
    // and a surface it cannot hash are both "could not establish", and neither
    // may become an error out of `run_hook` on an event nothing is meant to be
    // blocked at.
    let Ok(resolved) = resolve::resolve(here, overrides) else {
        return;
    };
    let Some(declared) = resolved.contract else {
        return;
    };
    let Ok(facts::Look::Is(current)) = contract::surface(&repo, &declared.tracked) else {
        return;
    };
    let session = envelope.session.as_deref();

    // No snapshot is the FIRST batch of this session. A session that started
    // after a change has already read the new files at start, and nudging it
    // about them is the noise that gets an advisory channel ignored — so the
    // seed is SILENT at `SessionStart`.
    //
    // AT ANY LATER EVENT THE SAME SEED IS NEWS (CLOUD-1085). This reporter serves
    // exactly two events and seeds at whichever arrives first, so seeding at
    // `PostToolBatch` means `SessionStart` never reached here — and the hosts
    // register the engine by bare name, so the usual cause is that no binary
    // resolved when that event fired. Every mediated call until one did failed
    // open in silence, and this is the only place that difference is observable.
    //
    // Recorded before the emit, for the reason the drift notice below gives: the
    // write is the rate limit, and erring toward one missed notice beats erring
    // toward an unbounded repeat of the same one.
    let facts::Look::Is(previous) = contract::previous(&git_dir, session) else {
        drop(contract::record(&git_dir, session, &current));
        if !matches!(envelope.event, hook::Event::SessionStart) {
            // WARNING: the engine is not mediating this session at all, which is
            // the one advisory whose subject is the gate rather than the work.
            advice.push(advisory::Advice::new(
                severity::AdvisoryTier::Warning,
                contract::unmediated_session(),
            ));
        }
        return;
    };

    let change = contract::compare(&previous, &current);
    if change.is_empty() {
        return;
    }
    // Recorded BEFORE the emit: a notice the agent saw and the snapshot did not
    // record is a notice the next batch repeats, which is precisely the nagging
    // this bound exists to stop. Erring toward one missed reminder beats erring
    // toward an unbounded stream of the same one.
    // An unwritable snapshot costs a repeated notice, never a refused call.
    drop(contract::record(&git_dir, session, &current));
    advice.push(advisory::Advice::new(
        severity::AdvisoryTier::Caution,
        contract::render(&change, &declared.wiring),
    ));
}

/// What this call's write would land, resolved only if a row asks (CLOUD-758).
///
/// The narrowing IS the cost argument. `facts::PROSPECTIVE` is `read` rather
/// than `free` because the edit shape needs the file off disk, and that price is
/// only acceptable because a repository declaring no content-keyed row — and any
/// call that is not a write — never pays it. Same discipline as
/// `Policy::required_checks_for` and `Policy::key_base_for`, which is CLOUD-460's
/// lesson: a call no row selects for does less work than `--help`.
///
/// The un-asked answer is `CouldNotLook` rather than an empty string, because
/// "nobody looked" and "the write is empty" are different claims and a content
/// predicate must never confuse them.
/// How many tracked artifacts this call's measured projection names (CLOUD-925).
///
/// **The column test comes before any work**, so a repository declaring no
/// `tracked-artifacts` ceiling pays one pass over rows it has already loaded and
/// touches neither git nor the filesystem — CLOUD-460's shape, applied to the one
/// unit of this feature that acquires anything.
///
/// `None` throughout means could-not-look, which allows: a ceiling that could not
/// count must not refuse. That is deliberately distinct from `Some(0)`, which is
/// "counted, and it names nothing".
///
/// The candidate set is derived from the projection exactly as the shell guard
/// derived it — path-shaped tokens, then the intersection with the tracked set —
/// and the consumer's own shorthand is applied first through the row's `resolves`
/// table, so no reference convention reaches this crate (non-negotiable rule 1).
/// The two facts whose subject is the SESSION rather than the call.
///
/// Paired because `run_hook` is at its 100-line ceiling and that ceiling is
/// right — it is the hottest function in the binary and every line in it is read
/// by somebody diagnosing a mediated call. The pairing is also honest rather than
/// arbitrary: a task receipt is minted once per session and a transcript is the
/// session's own record, so neither is a property of the call being judged.
fn session_facts(
    policy: &hook::Policy,
    envelope: &hook::Envelope,
) -> (
    taskset::TaskFacts,
    facts::Look<std::collections::BTreeMap<String, usize>>,
) {
    (
        task_facts(policy, envelope),
        extracted_facts(policy, envelope),
    )
}

/// Count what a declared extractor asks for in this session's transcript
/// (CLOUD-1172).
///
/// **The transcript is the one the HOST handed over**, which is what bounds this
/// to the session being mediated: there is no configured path and no way to name
/// another session's record. A repository declaring no extractor opens nothing.
///
/// **Could-not-look is the common case rather than the edge one** (CLOUD-388:
/// transcripts die with their container), and its spellings collapse to the same
/// answer here — no path on the envelope, a host that keeps none, a file that
/// will not parse, and nobody having asked. What none of them collapses into is a
/// COUNT OF ZERO, which is a real answer and means the extractor ran.
///
/// **The fifth spelling is per EXTRACTION rather than per transcript**
/// (CLOUD-1344): a transcript that parses but whose host records none of the
/// events one extraction reduces. That key is omitted from the map, so the module
/// reads undefined for it while every other declared extraction still answers —
/// a granularity the whole-transcript states cannot express.
///
/// Counts and nothing else leave this function. `transcript::Counts` is built
/// from typed fields — a tool result's own `is_error`, a hook run's exit code —
/// so no span of session text is read even internally, which is where rule 4 is
/// decided for this family.
fn extracted_facts(
    policy: &hook::Policy,
    envelope: &hook::Envelope,
) -> facts::Look<std::collections::BTreeMap<String, usize>> {
    let declared = policy.declared_extracts();
    if declared.is_empty() {
        return facts::Look::CouldNotLook;
    }
    let Some(path) = envelope.transcript.as_deref() else {
        return facts::Look::CouldNotLook;
    };
    let Ok(body) = std::fs::read_to_string(path) else {
        return facts::Look::CouldNotLook;
    };
    // POINTER-ONLY EVEN ON FAILURE: `parse` reports a `<label>:<line>` pointer
    // and never the line, and the label here is the path the host named rather
    // than anything read out of the file.
    let Ok(stream) = transcript::parse(&body, path) else {
        return facts::Look::CouldNotLook;
    };
    // PER-EXTRACTION COULD-NOT-LOOK (CLOUD-1344). An extraction this host records
    // none of the events for is OMITTED rather than answered zero, so a module
    // reading it gets undefined — which Rego takes as does-not-hold, the same
    // answer an undeclared extractor gives. Reporting a zero there would be a
    // real count meaning the extractor ran, over a session nobody measured.
    facts::Look::Is(
        declared
            .iter()
            .filter_map(|row| row.count.of(&stream).map(|count| (row.id.clone(), count)))
            .collect(),
    )
}

/// Mint the task receipt at session start, and read it on every other event
/// (CLOUD-856).
///
/// **Both halves in one function because they are one decision**, and splitting
/// them is how the mint and the read come to disagree about which manifests
/// count. `run_hook` is at its line ceiling besides, and that ceiling is right:
/// it is the hottest function in the binary and every line in it is read by
/// somebody diagnosing a mediated call.
///
/// The mint is where the unbounded work lives, which is the whole of this row's
/// answer — session start carries no verdict on any host, so nothing waits on it
/// and a failure cannot become the reason a session stops. The record simply
/// stays unwritten and every reader answers could-not-look, which is the
/// direction this fact must fail in.
///
/// The read is behind the same narrowing `pinned` uses, one term tighter: only a
/// row that NAMED a manifest reads it, so a repository with mediated modules and
/// no `[[rule.tasks]]` opens nothing.
fn task_facts(policy: &hook::Policy, envelope: &hook::Envelope) -> taskset::TaskFacts {
    if envelope.event == hook::Event::SessionStart {
        // Returned rather than discarded: the session that mints it may as well
        // have it, and a caller that ignores it is not paying for the read twice.
        return taskset::refresh(hook_authority_root(), &policy.declared_tasks());
    }
    if !policy.reads_tasks(envelope) {
        return facts::Look::CouldNotLook;
    }
    taskset::cached(hook_authority_root())
}

fn manifest_for(policy: &hook::Policy, envelope: &hook::Envelope) -> hook::ManifestFacts {
    let rule = policy.manifest_ceiling_for(envelope)?;
    let value = rule.measures?.read(envelope)?;
    let root = git::repo_root(&std::env::current_dir().ok()?).ok()?;
    let tracked = git::tracked_paths(&root).ok()?;
    Some(hook::count_named_artifacts(
        &value,
        &rule.resolves,
        &tracked,
    ))
}

fn prospective_for(policy: &hook::Policy, envelope: &hook::Envelope) -> hook::ProspectiveFacts {
    if policy.reads_prospective(envelope) {
        hook::prospective_facts(hook_authority_root(), envelope)
    } else {
        facts::Look::CouldNotLook
    }
}

fn drain_advisories(
    envelope: &hook::Envelope,
    overrides: &Overrides,
    mode: Mode,
    err: &mut dyn Write,
    advice: &mut Vec<advisory::Advice>,
) -> Result<()> {
    // The repository, resolved through the one finder (CLOUD-824). This read
    // asked TWO different questions before: whether an authority sits in the cwd,
    // and where the repository is — so in a linked worktree with no committed
    // authority of its own the drain returned early while the store it wanted was
    // bound perfectly well one directory up.
    let here = hook_authority_root();
    if !here.join(config::CONFIG_FILE).exists() {
        return Ok(());
    }
    let Ok(repo) = git::repo_root(here) else {
        return Ok(());
    };
    let Some(dir) = store::bound_dir(&store::resolve(&repo)?) else {
        return Ok(());
    };
    let Some(session) = envelope.session.as_deref() else {
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            "hook: the host reported no session, so the advisory drain has no \
             boundary to coalesce against; nothing drained",
        )?;
        return Ok(());
    };

    let config = resolve::resolve(here, overrides)?.drain.unwrap_or_default();
    let access = journal::open(&dir)?;
    let seqno = access.format().seqno;
    let mut state = drain::load_wake(&dir, session);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| {
            u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
        });

    match drain::decide_wake(&state, &config, now_ms, seqno) {
        drain::Wake::Coalesced => {
            state.coalesce();
            drain::save_wake(&dir, session, &state)?;
            return Ok(());
        }
        // Nothing is read, which is the whole saving: the give-up is measured
        // against a one-file format read that has already happened above.
        drain::Wake::GaveUp => return Ok(()),
        drain::Wake::Drain => {}
    }

    // The ref this checkout is on, so the count shown is the one for the tree in
    // front of the agent. A detached `HEAD` has none, and the cycle falls back to
    // a deterministic instance rather than to silence.
    let context = git::current_branch(here)?
        .map(|branch| findings::Context::new(format!("refs/heads/{branch}")));
    let records = findings::load_all(&dir)?;
    let drained = drain::cycle(
        &records,
        &git::changed_paths(here)?,
        context.as_ref(),
        &config,
        &state.counts,
        // The emission policy's whole input (CLOUD-165). Read with `all` rather
        // than `since`, because a ratio is computed over a window of the history
        // and a cursor read would hand back a delta and take a position this
        // process has no business holding — the drain's cursor is the lineage's.
        &journal::all(&dir),
    );

    // Persist before emit. A degraded store cannot record the suppression, and
    // must not: writing a record version it cannot represent would drop fields.
    // The emission still happens — dedupe and reporting work read-only — so the
    // agent is not silenced by an out-of-date binary.
    if access.is_writable()
        && drain::journal_suppressions(&dir, &journal::shard_id(here), &drained)? > 0
    {
        // Fold the entries into their records now rather than leaving them for
        // whenever `state record` next runs. Two reasons, and the second is the
        // load-bearing one: the false-positive rate reads the *records*, so an
        // unfolded suppression is invisible to the measurement it exists for;
        // and `record_suppressions` skips a record that already carries the
        // disposition, which only stops the per-drain re-append once the fold
        // has happened. A lost lock race is not a failure — the entries are
        // already durable in this worktree's shard and the next fold picks them
        // up — so it is silent here rather than reported, since a hook that
        // narrated its own bookkeeping to an agent would be spending context on
        // a non-event.
        let _ = journal::merge(&dir)?;
    }

    // The `resultId` cheap path (CLOUD-166), measured against the LINEAGE's
    // watermark rather than this session's own bookkeeping, so a warm fork does
    // not re-list the set its parent had just shown.
    let root = session::root(&dir, session)?;
    let previous = session::load_watermark(&dir, &root)?;
    let repeat = previous
        .as_ref()
        .is_some_and(|mark| mark.result_id == drained.result_id);

    // **Persistence is never skipped, which is the half the short-circuit must
    // not take with it.** The ordinal advances on every cycle including this one,
    // so a reader can tell a repeated cycle from a cycle that never ran — and the
    // flap rate that divides by it stays honest. Written before the emit, for the
    // same reason the suppressions above are.
    session::save_watermark(
        &dir,
        &root,
        &session::Watermark::next(previous.as_ref(), drained.result_id.clone()),
    )?;

    // Three outcomes, and the middle one is what CLOUD-166 adds: say the payload,
    // say `unchanged`, or say nothing. A repeat answers with the fixed marker
    // rather than silence, because silence is indistinguishable from a drain that
    // never ran. Nothing found still says nothing — that is a different claim.
    let emitted = !drained.lines.is_empty() && !repeat;
    // Persist before emit, on the emitting side too (CLOUD-165): an emission the
    // agent saw and the log did not record is an emission the re-emit cap cannot
    // count, so the flood the cap exists to stop would be invisible to it. Written
    // only when the payload actually reaches the agent — an `unchanged` boundary
    // showed nothing and must not spend the cap.
    if emitted
        && access.is_writable()
        && drain::record_emissions(&dir, &journal::shard_id(here), &records, &drained.counts)? > 0
    {
        let _ = journal::merge(&dir)?;
    }
    // The channel, chosen by the capability table rather than by this module
    // (CLOUD-461). Until it existed the drain wrote to **stderr**, which on
    // Claude Code is not shown to the model on exit 0 — so the one thing in the
    // engine whose entire purpose is to report findings back to the agent was
    // reporting them where the agent could not read them. `emit_advisory` puts
    // both outcomes on the surface the host actually delivers, and keeps stderr
    // for the hosts that declare no channel, where it is still the operator's.
    if emitted {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Advisory,
            drain::render(&drained),
        ));
    } else if repeat && !drained.lines.is_empty() {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Advisory,
            drain::UNCHANGED,
        ));
    }

    // Volume and suppression counts are the operator's, not the agent's: they
    // say how the drain is behaving, which is a diagnostic about Batten rather
    // than a finding about the repository. They travel on the `batten: ` channel
    // at the verbose rung, so the default path — the one an agent reads — spends
    // nothing on them (§5). Routing them into `systemMessage` proper rides
    // CLOUD-44's per-host emitter shims.
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!(
            "hook: drained {} line(s); withheld {} out of scope, {} over the cardinality cap, {} \
             over the token budget, {} flapping; {} rule(s) with a flapping identity",
            drained.lines.len(),
            drained.scope_filtered.len(),
            drained.capped.len(),
            drained.over_budget.len(),
            drained.flap_suppressed.len(),
            drained.flapping.len(),
        ),
    )?;

    state.drained(now_ms, seqno, &drained, emitted);
    drain::save_wake(&dir, session, &state)?;
    Ok(())
}

/// Resolve the mediated-call policy for this run.
///
/// **Absent authority is the empty policy, not an error.** `batten hook` is
/// registered once and then mediates every call in whatever directory the agent
/// happens to be in, most of which are not Batten repositories; refusing there
/// would make the guard the reason ordinary work stops.
///
/// An authority that exists and **cannot be read** is the opposite case, and it
/// propagates: a policy file that does not parse means the rules the operator
/// wrote are not being applied, and silently allowing would be the false green
/// this engine exists to catch. It surfaces as a [`UsageError`] — exit `1`, loud
/// on stderr, and structurally not a deny, because §7 spends `2` on the verdict
/// alone.
/// Record an agent-sourced fact, if this post-tool call is one a declared fact
/// asked for (CLOUD-776).
///
/// The command comparison is byte equality against the DECLARED command, the same
/// value [`facts::sourced`] later verifies the record against — so a call that
/// merely resembles the request records nothing, rather than recording something
/// the reader would then have to reject.
///
/// Rule 4 is satisfied here rather than downstream: [`facts::rows_declared`]
/// reduces the buffer to a count at this boundary, and the count is what is
/// written. No byte of a tool's stdout — the likeliest place in the envelope for
/// a secret — reaches disk.
///
/// # The declaration is resolved BEFORE the buffer is read, and the order is the
/// contract
///
/// [`facts::rows_declared`] needs the row's `returns`, so the policy load and the
/// command match come first and the count second. The reverse order is what
/// CLOUD-993 shipped and it made the field dead config: `rows_in` was still the
/// reader, so a row could declare `json-array` and a command emitting prose would
/// still record one opaque row — a `rows == 0` gate silently unsatisfiable, over a
/// declaration nobody read. Naming a contract and then not checking it is worse
/// than never offering the field.
///
/// Every failure is silent. A hook that cannot record a fact must not become the
/// reason work stops: the next attempt denies again with the same `Fix::Run`,
/// which is the safe direction and one the agent can see.
fn record_agent_fact(overrides: &Overrides, envelope: &hook::Envelope) {
    let Ok((policy, _)) = load_policy(overrides, hook::Harness::ExitCode) else {
        return;
    };
    // EVERY MATCHING ROW, not the first (CLOUD-690). `find` was correct while a
    // selector was a command — two rows cannot declare one byte-identical command
    // without being the same row — and it is WRONG for a tool: one tool serves
    // several methods whose results answer different questions, so two rows
    // legitimately share a selector and discriminate by the SHAPE of the result.
    // Measured: `review-answered` and `review-happened` both name
    // `pull_request_read`, and under `find` the second could never record at all —
    // its check denied forever and reading the reviews did not satisfy it.
    //
    // Which of the matching rows a given result actually answers is `counted`'s to
    // decide, one row at a time: a row whose `counts` path is absent from this
    // payload answers could-not-look and records nothing, which is exactly the
    // discrimination that makes sharing a selector safe.
    for declared in policy
        .declared_facts()
        .iter()
        // EITHER SELECTOR, asked of the row rather than compared here: a `command`
        // row is byte-equality on what the agent ran, a `tool` row is the host's
        // own attribution. Keeping the choice inside `Declared` is what stops this
        // site and the deny site disagreeing about which calls answer a fact.
        .filter(|declared| declared.answered_here(&envelope.raw_tool, &envelope.command))
        // AND THE CALL, not merely the tool (CLOUD-690). Shape was doing this job
        // and shape is a proxy: measured, `pull_request_read`'s `get_reviews` and
        // its `get_files` both answer with a bare top-level array, so a row
        // counting `.` over the tool recorded `rows 3` from a FILE listing and
        // satisfied the check that asks whether a review exists. The method is an
        // argument, and the argument is here in the envelope — so this is asked
        // where it can be answered rather than inferred one layer later.
        .filter(|declared| declared.selected_by(&envelope.input))
    {
        record_one_agent_fact(&policy, envelope, declared);
    }
}

/// Write the record one declared fact earns from this result, or nothing.
///
/// Extracted from [`record_agent_fact`] when that site went from one matching row
/// to every matching row (CLOUD-690): the loop body is a decision about ONE row,
/// and every early return below means "this row is not answered here" rather than
/// "stop looking". Inlined, the first `return` would have abandoned the rows after
/// it — which is the same one-of-many defect the `find` it replaced had.
fn record_one_agent_fact(
    policy: &hook::Policy,
    envelope: &hook::Envelope,
    declared: &facts::Declared,
) {
    // A buffer that said nothing at all — absent, or empty — is `CouldNotLook`
    // and records NOTHING. Writing a zero here would turn "the tool printed
    // nothing" into the fact "there are none", which is the guessed-envelope
    // failure the whole capability table exists to prevent.
    //
    // CHECKED against the row's declaration rather than inferred from the bytes
    // (CLOUD-993): a buffer that does not match what the row said it returns is
    // `CouldNotLook` and records nothing, so a command that quietly stops
    // emitting JSON denies loudly instead of recording a plausible number.
    // `opaque` is where the inferring reader stays available, and it has to be
    // said.
    //
    // `counted` rather than `rows_declared` (CLOUD-690): a row declaring `counts`
    // is asking how many elements of one collection satisfy its predicate, and a
    // whole-result count answers a different question — measured, over an
    // unfiltered review-thread array it counts the answered threads too, so a
    // clear head reads as blocking. A row declaring no `counts` falls straight
    // through to the reading above, which is Acceptance's backward-compatibility
    // clause and is asserted rather than assumed.
    let facts::Look::Is(rows) = facts::counted(&envelope.result, declared) else {
        return;
    };
    let record = facts::Sourced {
        // What ANSWERED it, which is the command for one selector and the tool for
        // the other. `sourced` compares against the same accessor, so the writer
        // and the reader cannot disagree about what a satisfied record looks like.
        command: declared.answered_by().to_owned(),
        // The clock is read HERE, at the boundary, for the reason every other
        // clock read in this crate is: a predicate that read one would stop being
        // a pure function of its inputs. The stamp is provenance beside the
        // answer — `facts::sourced` never consults it.
        seen_at: receipt::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since_epoch| since_epoch.as_secs()),
        ),
        rows,
    };
    // FILED UNDER THE KEY THE DECLARING ROW STATES (CLOUD-859), resolved
    // policy-wide because this envelope is the fact's own command and not the
    // call the receipt row selects — a call-scoped lookup finds nothing here.
    // A fact no receipt row requires is unreadable by anything, so recording it
    // would leave a file nobody consults; that is silent like every other
    // failure on this path.
    let Some(key) = policy.receipt_key_for_check(&declared.name) else {
        return;
    };
    let _ = receipt::record_sourced(
        &declared.name,
        key,
        policy.named_receipt_subject(envelope).as_deref(),
        &record,
    );
}

/// Everything the post-tool event records, in the order it must happen.
///
/// Extracted from [`run_hook`] because the workspace's function-length lint asked
/// for it, and the lint was right: this is one decision — what a completed call
/// leaves behind — and `run_hook`'s body is a sequence of stages, not a place to
/// spell one out.
///
/// **The capture is first, and textually first is the point.** CLOUD-917 makes it
/// the authoritative record and the row count a derived view of it, so projecting
/// first would permit a build where the count survived and the bytes did not.
fn record_post_tool(
    overrides: &Overrides,
    envelope: &hook::Envelope,
    harness: hook::Harness,
    advice: &mut Vec<advisory::Advice>,
) {
    // GATED ONLY ON THE RESPONSE MEMBER, never on the command. The
    // `!command.is_empty()` conjunct below is correct for a FACT — a fact is
    // keyed to a command that ran — and wrong for a capture, because the
    // response of a structured tool is still a response. That conjunct is why
    // every MCP call, every `Read` and every `Write` is missed today.
    //
    // A host that literally sends `"tool_response": null` is indistinguishable
    // from one that sends no member at all, because `decode`'s alias walk
    // produces `Value::Null` for both. Accepted rather than papered over:
    // telling them apart is `decode`'s work and buys nothing any surveyed host
    // produces.
    if envelope.result.is_null() {
        // ABSENT IS A RECORD, not silence (CLOUD-917). Without this row a host
        // that sends no response is indistinguishable from a call nobody made,
        // which is the two-outcomes-into-one collapse the empty case is careful
        // about at the other end. Only on `PostTool`, so the pre-tool path — which
        // is nearly every call — still does no work here.
        record_absent_response(envelope, harness, advice);
    } else {
        capture_response(envelope, harness, advice);
    }
    // CLOUD-776's gate was `!envelope.command.is_empty()`, on the premise that a
    // fact is keyed to a command that ran. **CLOUD-690 retired that premise and
    // the gate outlived it**, which made `tool` a column accepted at load and
    // unread at record time: an MCP call carries no command, so a `tool`-selected
    // row never reached `record_agent_fact` at all and its check denied forever.
    // Measured by `tests/review-answered.bats` the moment its fact was re-sourced
    // — six cases red with the record never minted — and it is the same
    // accepted-and-unread shape as CLOUD-993 and CLOUD-859, one site further in.
    //
    // The cheap question that replaces it is `record_mints`' own: a post-tool
    // event carrying no result answers nothing, whichever selector a row uses, so
    // no config work is done for one. Which calls answer a fact stays
    // `Declared::answered_here`'s to decide, which is what keeps this site and the
    // deny site from disagreeing.
    //
    // The cost, stated rather than absorbed: a post-tool call carrying a result
    // now loads the policy here AND in `record_mints`. That is one extra load on
    // an event that is already reading and storing a buffer, and it is off every
    // path `perf-assert` budgets — all of which are pre-tool or `check`. A shared
    // load across the three recorders is the right shape and is not this change.
    if !envelope.result.is_null() {
        record_agent_fact(overrides, envelope);
    }
    // CLOUD-1024's, on the other selector. Keyed to the TOOL rather than to a
    // command, so it fires on exactly the calls the conjunct above excludes: an
    // MCP call carries no command and is the whole point here.
    record_mints(overrides, envelope);
    // CLOUD-1051's, on the same selector and after it. A mint renders a closed
    // template; a recorder may additionally run a declared program and record
    // what it decided, which is what a board write's refinement column IS.
    // Ordered after so a recorder can never be the reason a receipt goes
    // unwritten — the two are independent, and the cheaper one goes first.
    write_records(overrides, envelope);
}

/// The end-of-turn rules that are not a module, ranked (CLOUD-1051).
///
/// # What this replaces, and why the ranking is here rather than in config
///
/// `mise-tasks/stop-guard.sh` ran five rules in a fixed order and emitted **at
/// most one**, because two nudges on one turn is how a channel stops being read.
/// Four of them cannot be a `mediated_call` module: three spawn a sibling
/// program and one reads the tree, and `RuleKind::scopes` pairs every spawning
/// kind with `RuleScope::Tree` alone. So they live here, in the order the shell
/// ranked them — by MEASURED precision, `stop-posture` at 3/3 leading
/// `finding-sink` at 1/1, with the three unmeasured below — and the caller emits
/// the first that speaks.
///
/// # The siblings are spawned unchanged, which is a deliberate bound
///
/// `finding-sink-check.sh` and `unlanded-check.sh` are invoked exactly as the
/// bash invoked them, with the same stdin. Neither enters this change's
/// changed-file set, so `shell-retirement` never fires on them and the cascade
/// stops at the program actually being retired. A `[[hook.handler]]` row cannot
/// serve here: that door pipes the host's own payload, and the first of those
/// two reads a transcript PATH on stdin — it would answer "no readable
/// transcript path" every turn, which is a broken gate wearing a nudge's shape.
///
/// # Everything fails open, and every failure is silent
///
/// This runs at `Stop`. A routine that errored, blocked or printed would put the
/// end-of-turn check on the path that must stay free — committing and pushing to
/// a draft is what survives a container reclaim. So every unreadable path,
/// missing program and unresolvable branch yields `None`.
fn stop_nudges(overrides: &Overrides, envelope: &hook::Envelope) -> Option<String> {
    if envelope.event != hook::Event::Stop || envelope.stop_active == Some(true) {
        return None;
    }
    if std::env::var_os(STOP_GUARD_BYPASS).is_some() {
        return None;
    }
    // NO ADVISORY WHOSE REMEDY THIS TURN MAY NOT PERFORM (CLOUD-895).
    //
    // Every rule below ends in a write — "Land it", "file it", "Finish it now",
    // "Close the punts" — so in plan mode the whole ladder names actions the
    // agent is forbidden to take on the turn it is told to take them. That is
    // worse than saying nothing: `additionalContext` is delivered AFTER the
    // user's message, so it is the freshest instruction in context, and a
    // machine-generated imperative the recipient cannot obey trains the recipient
    // to override the channel a real refusal arrives on (CLOUD-339).
    //
    // MECHANICAL, NEVER AN INFERENCE FROM PROSE. The host declares the mode; this
    // reads it. Deciding from the user's wording whether they "meant" a read-only
    // turn would be the model verdict non-negotiable rule 3 forbids.
    //
    // ABOVE THE SEAM WRITES ON PURPOSE? NO — deliberately below them. The links
    // and the state mint are the engine's own record rather than advice to the
    // agent, and a plan-mode turn still happened: suppressing the RECORD would
    // make `doctor session` answer could-not-look over a session it watched, which
    // is the distinction CLOUD-1372 spent a rule on. Only the SPEAKING half is
    // suppressed.
    let root = &hook_authority_root();
    // THE TRANSCRIPT SEAM, and it is a WRITE this routine owes rather than a rule
    // (CLOUD-990). `[transcript].path` names one fixed repo-relative path because
    // the key is the committed authority and is deliberately unlayerable — a
    // local file redirecting it would be CHOOSING THE EVIDENCE. The host's
    // transcript is a per-session absolute path no committed value can name, so
    // the indirection lives at the boundary: the authority names the file
    // forever, and this points it at the session the host just named.
    //
    // NOTHING IS READ HERE. The symlink is a pointer; the engine is the only
    // thing that opens it. The retired shell hook was the ONLY writer, so
    // dropping this would have left `batten check`'s transcript capability
    // reading a dangling path on every fresh container — the CLOUD-990 condition,
    // reintroduced by the retirement that was supposed to preserve it.
    refresh_transcript_link(root, envelope);
    // THE SAME SEAM FOR THE SESSION'S TASK STORE (CLOUD-1376), and it rides here
    // for the transcript's reason rather than as a second idea: both are
    // per-session paths outside the root that a committed key must name forever.
    // A session that has not reached its first `Stop` therefore has no link and
    // `doctor session` answers could-not-look — which is the honest reading, and
    // the one the whole row exists to keep distinct from a clean.
    //
    // ABOVE THE MINT AND THE LADDER, on CLOUD-1372's own reasoning one step
    // earlier: a seam WRITE must not sit behind a rule that can return, or the
    // link goes unwritten on exactly the turns a rule fired — and an unwritten
    // link reads as could-not-look forever after.
    refresh_tasks_link(root, envelope);
    // MINTED BEFORE ANY RULE CAN RETURN (CLOUD-1372). The position is the fix,
    // not a tidy-up.
    //
    // This call used to live inside the unlanded rule, four early-returns down
    // the ladder. So a branch carrying any finding-sink or filed-here pointer
    // returned first and the completion verdict was never MINTED — not decided
    // "landed", not recorded "could not look", simply absent. Measured on the
    // session that found this: 20 findings in the store, ten of them
    // `filed-over-own-diff` (which returns at the old rule 3), and zero
    // `completion.unlanded` rows across a session that stopped on an unlanded
    // branch repeatedly.
    //
    // MINTING AND REPORTING ARE DIFFERENT QUESTIONS and must not share a
    // suppression. What the ladder decides is which ONE thing to say, because
    // two nudges is how a channel stops being read. What the store holds is what
    // was observed, and a reader — `land`, a later turn, a human — is entitled to
    // that whether or not this turn chose to speak about it.
    if std::env::var_os(UNLANDED_BYPASS).is_none() {
        record_state(overrides);
    }
    // RULE 1 — a completion signal with no patch-id-equivalent commit on the
    // landing target. FIRST, and the order is a claim about consequence.
    //
    // It was rule 4, behind two prose-shaped readings. That ranking was by
    // MEASURED PRECISION, which is the right axis for choosing between rules that
    // are equally about the turn's conduct — but this one is not about conduct.
    // The others say the turn was untidy; this one says the work does not exist
    // anywhere but here, and a container reclaim ends it. A style nit outranking
    // that is the inversion CLOUD-1372 records, and it is the ladder's own
    // "at most one nudge" budget that made the ordering load-bearing rather than
    // cosmetic.
    if !envelope.writes_available() {
        return None;
    }
    if std::env::var_os(UNLANDED_BYPASS).is_none()
        && let Some(pointer) = unlanded_pointer()
    {
        return Some(format!(
            "{pointer}\nThis turn declared a stopping point and the work is not on the landing \
             target. Land it, or say what blocks it."
        ));
    }
    // RULE 2 — a finding stated in prose with nothing durable written. It reads
    // the transcript, so it reaches prose the module above cannot see: the final
    // text block is under half a turn's assistant prose.
    if let Some(path) = envelope.transcript.as_deref()
        && let Some(pointer) = spawn_reading(root, "mise-tasks/finding-sink-check.sh", path)
    {
        return Some(format!(
            "{pointer}\nA finding was stated here and nothing durable was written. Go re-derive \
             it and file it, or confirm it is already tracked."
        ));
    }
    // RULE 3 — a row this branch filed names a file this branch is changing. The
    // same predicate `land` decides on, run here so the punt surfaces at the end
    // of the turn that created it rather than when a runner is about to be spent.
    //
    // ONCE PER ROW PER BRANCH. A Stop hook sees no PR body, so repeating one
    // pointer every turn for the rest of a session is exactly how this channel
    // dies. The turn the overlap first appears is the one that can still act
    // cheaply, which is the whole reason for running it ahead of `land`.
    if let Some(fresh) = filed_here_pointers(overrides, root, Suppression::PerRow) {
        return Some(format!(
            "{fresh}\nA row this branch filed names a file this branch is changing. Finish it \
             now while the file is open, or make sure the PR body closes it when you land."
        ));
    }
    // RULE 4 was the completion reading and is now RULE 1, at the top of this
    // function (CLOUD-1372). Its hatch is unchanged and still shared with the
    // recorder that feeds it: a caller who switched the rule off must not still
    // pay a tree walk and a store write per turn for an answer nobody reads.
    //
    // RULE 5 — every row this branch spun off, enumerated for re-evaluation.
    // Rule 3 asks a narrow measured question and answers it once per row; this
    // asks the broad one no predicate scores (non-negotiable rule 3): here is the
    // whole set, say for each that it is genuinely independent work.
    //
    // SUPPRESSED ON THE SET, NOT PER ROW, and that is the whole difference. A
    // per-row receipt would show a partial list, and a checklist with rows hidden
    // is not a checklist. File another row and the whole list is asked again,
    // because the question is about the set.
    let rows = filed_here_pointers(overrides, root, Suppression::PerSet)?;
    Some(format!(
        "{rows}\nEvery row above was spun off while this branch was open. For each, by number: \
         is it genuinely independent work, or a punt you could close here? Close the punts; \
         leave a reason for the rest."
    ))
}

/// Point the committed transcript path at the session the host just named.
///
/// The declared path is the consumer's `[transcript].path` — read from config
/// rather than assumed, because the authority names the file and this only
/// refreshes what it points at. A repository declaring none has nothing to link.
///
/// Silent on every failure, like everything else at this boundary: no config, no
/// declared path, an unreadable source, an unwritable link. A transcript that
/// cannot be pointed at resolves to `Capability::Absent` downstream, which is
/// silence rather than a verdict.
fn refresh_transcript_link(root: &Path, envelope: &hook::Envelope) {
    let Some(source) = envelope.transcript.as_deref() else {
        return;
    };
    if !Path::new(source).is_file() {
        return;
    }
    let Ok(config) = resolve::resolve(root, &Overrides::default()) else {
        return;
    };
    let Some(declared) = config
        .transcript
        .as_ref()
        .and_then(|transcript| transcript.path.as_deref())
    else {
        return;
    };
    let link = root.join(declared);
    if let Some(parent) = link.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // Replaced rather than updated in place: `symlink` refuses an existing path,
    // and the old target is a session that has ended.
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(source, &link);
}

/// Point the derived task-store link at the session the host just named.
///
/// The same seam as [`refresh_transcript_link`] and for the same reason: the
/// store is per-session and outside the root, so no committed value can name it,
/// while the committed value must name it forever. The declared template is the
/// consumer's; the one substitution is the engine's (CLOUD-1376).
///
/// NOTHING IS READ HERE — the symlink is a pointer, and `doctor session` is the
/// only thing that opens it. Silent on every failure, like everything else at
/// this boundary: a store that cannot be pointed at resolves to could-not-look
/// downstream, which is an honest absence rather than a clean.
fn refresh_tasks_link(root: &Path, envelope: &hook::Envelope) {
    let Some(session) = envelope.session.as_deref() else {
        return;
    };
    let Ok(config) = resolve::resolve(root, &Overrides::default()) else {
        return;
    };
    let Some(transcript) = config.transcript.as_ref() else {
        return;
    };
    let (Some(template), Some(declared)) =
        (transcript.tasks.as_deref(), transcript.path.as_deref())
    else {
        return;
    };
    // `_source` on a platform with no symlink, because the only reader below is
    // `#[cfg(unix)]`. It was consumed unconditionally by an `is_dir` check until
    // CLOUD-1435 removed that guard, so dropping the guard made this
    // `unused_variables` on Windows — and `cross-check` denies warnings
    // (CLOUD-397), so it is an error there and clean on the host that builds it.
    //
    // The substitution stays OUTSIDE the `cfg`, deliberately: it is the boundary
    // resolving where the store would be, and a platform that cannot park a
    // pointer should still fail on a template it cannot substitute rather than
    // skip the question entirely.
    let source =
        crate::transcript::tasks_dir(template, session, std::env::var_os("HOME").as_deref());
    // CONSUMED ON A PLATFORM THAT CANNOT LINK, because the only real reader below
    // is `#[cfg(unix)]`. An `is_dir` check used to consume it unconditionally
    // until CLOUD-1435 removed that guard, so its removal made this
    // `unused_variables` on Windows, where `cross-check` denies warnings
    // (CLOUD-397). Renaming it `_source` traded that for
    // `clippy::used_underscore_binding` — a binding may be underscore-named or
    // used, never both — so the discard is explicit and cfg'd instead.
    #[cfg(not(unix))]
    let _ = &source;
    // PARKED ON SUBSTITUTION, NEVER ON THE TARGET EXISTING (CLOUD-1435). This
    // guard used to read `if !Path::new(&source).is_dir() { return }`, and it
    // withheld the pointer at exactly the moment the pointer was informative.
    //
    // The host creates the per-session store LAZILY, on the first task write. So
    // a session that declares no task has no directory, got no link, and
    // `doctor session` answered could-not-look for its whole life — measured on
    // this container, where `0` was unreachable for any session. A verb that
    // abstains on the common case is a dead gate: its answer stops carrying
    // information and nothing reports that it has.
    //
    // A DANGLING LINK IS THE HONEST POINTER, and the discrimination belongs to
    // the reader. This boundary knows where the store WOULD be; whether an absent
    // one means "no tasks written yet" or "the template does not describe this
    // host" has two answers, and `doctor::diagnose_session` is the one place that
    // decides between them. Withholding the link collapsed both into one silence.
    //
    // THE DIRECTORY IS NOT CREATED HERE. That would be this engine writing into
    // the host's own store to make its own reading succeed.
    let Some(link) = crate::transcript::tasks_link(root, declared) else {
        return;
    };
    if let Some(parent) = link.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let _ = std::fs::remove_file(&link);
    #[cfg(unix)]
    let _ = std::os::unix::fs::symlink(&source, &link);
}

/// The hatch that silences the whole end-of-turn surface.
///
/// One hatch for the set rather than one per rule, exactly as the retired shell
/// hook had it: these are five readings of one question — *is this turn actually
/// finished* — and a per-rule switch would let the surface be dismantled a rule
/// at a time with nothing reporting that it had been.
const STOP_GUARD_BYPASS: &str = "BATTEN_STOP_GUARD_BYPASS";

/// The hatch `unlanded-check` declares, ridden by the recorder that feeds it.
const UNLANDED_BYPASS: &str = "BATTEN_UNLANDED_CHECK_BYPASS";

/// Evaluate the completion detectors so rule 4 has something to read.
///
/// [`run_state_record`]'s own work, with its streams and its verdict discarded:
/// this is an EVALUATION, not a decision. A recorder that failed simply leaves
/// nothing to read, which is silence — the correct answer for a hook that may
/// never be the reason a turn stalls.
fn record_state(overrides: &Overrides) {
    let mut sink = std::io::sink();
    let _ = run_state_record(overrides, Mode::default(), &mut sink);
}

/// The `completion.unlanded` verdict for this branch, or nothing (CLOUD-1163).
///
/// # It decides NOTHING, which is the whole shape of the predecessor
///
/// [`completion::RULE_ID`] — a completion marker in the session transcript with no
/// patch-id-equivalent commit on the landing target — is [`record_state`]'s
/// verdict, minted two lines above this is called. This READS the store and
/// points at it. A re-derivation here would answer by ancestry where the engine
/// answers by patch identity, and a rebased-then-landed branch is clean to one
/// and dirty to the other.
///
/// # Why this stopped being a spawn
///
/// `mise-tasks/unlanded-check.sh` did exactly this by shelling to `batten state
/// list` and parsing the pointer lines back — from inside the engine that had
/// just written them. It read the PLAIN listing rather than `-J` because a
/// by-path hook gets no mise env and so has no pinned `jq`; in process there is
/// no listing to re-parse and no `jq` to want.
///
/// # Fail-open on everything except the observation
///
/// A detached HEAD, an unresolvable head, no bound store, an unreadable store:
/// all silence, because this runs inside a Stop hook and a nudge is never the
/// reason a turn stalls. The one CLOSED direction is the observation itself —
/// `skipped` and `errored` are the engine's words for "did not look", and a
/// question asked on the strength of a scan that never ran is the false green in
/// nudge form. Only an observed, positive count is a finding.
fn unlanded_pointer() -> Option<String> {
    let branch = git::current_branch(Path::new(".")).ok().flatten()?;
    let context = format!("refs/heads/{branch}");
    // THE REPO ROOT, NOT THE HOOK'S ANCHOR, and the two are not the same object.
    // `run_state_record` — which minted this verdict moments ago — keys the store
    // on `git::repo_root`, so a reader anchored anywhere else looks in a store
    // nothing wrote to and reports silence. Measured: the nudge went quiet over a
    // fixture whose `batten state list` showed the finding.
    let repo = git::repo_root(Path::new(".")).ok()?;
    let opened = store::resolve(&repo).ok()?;
    let dir = store::bound_dir(&opened)?;
    let records = findings::load_all(&dir).ok()?;

    let (identity, count) = records
        .iter()
        .filter(|record| record.rule == completion::RULE_ID)
        .flat_map(|record| record.instances.iter().map(move |i| (&record.identity, i)))
        .filter(|(_, instance)| instance.context.to_string() == context)
        .find_map(|(identity, instance)| match instance.occurrences {
            // FAIL-CLOSED ON THE OBSERVATION, and this is the arm that carries it.
            findings::Observation::Observed(count) if count > 0 => Some((identity, count)),
            _ => None,
        })?;

    // ONCE PER CLAIM, AND THE KEY IS NOT ONE THE REMEDY CAN MINT (CLOUD-890).
    //
    // This keyed on `git rev-parse HEAD`, and its own nudge says "Land it, or say
    // what blocks it." The agent commits; HEAD moves; the key is void; the nudge
    // fires again — so under "commit early and often" EVERY REMEDIAL ACTION
    // RE-ARMED THE ALARM. A dedup key the recipient can mint by doing what it was
    // asked is not a suppression key, it is a retrigger, and the level-vs-edge
    // reading is the same one ISA-18.2 makes shelving a first-class state for:
    // `¬landed` is a level that holds continuously, and the agent cannot clear it
    // within the turn it is asked to.
    //
    // The finding's own identity is the claim instance: `completion::identity`
    // hashes the RULE, its pattern key and the SESSION, so committing does not
    // move it and no action the agent takes mints a fresh one. A NEW session asks
    // again, which is right — it has not been told yet — and landing the work
    // resolves the finding at the source, which is where a level is supposed to
    // clear.
    //
    // The receipt still lives beside the lease and board-write records in the git
    // dir, out of the tree, so a nudge never dirties the worktree it asks about.
    let key = identity.fingerprint.to_hex();
    let seen = git::git_dir(Path::new(".")).ok().map(|dir| {
        dir.join("batten-receipts")
            .join(format!("unlanded-nudged.{}", branch.replace('/', "-")))
    });
    if let Some(path) = seen.as_deref() {
        if std::fs::read_to_string(path).is_ok_and(|seen| seen.lines().any(|line| line == key)) {
            return None;
        }
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        // Best-effort: an unwritable receipt costs a repeated nudge, never the
        // nudge itself, so it must not swallow the finding.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .and_then(|mut file| {
                std::io::Write::write_all(&mut file, format!("{key}\n").as_bytes())
            });
    }
    Some(format!(
        "unlanded: {count} commit(s) not on the landing target ({})",
        completion::RULE_ID
    ))
}

/// What the `filed-here` row says about this branch, suppressed and rendered.
///
/// # Two questions over one predicate, which is what keeps them from drifting
///
/// [`Suppression::PerRow`] answers the narrow one — which filed row names a file
/// this branch is holding open — from the row's own findings.
/// [`Suppression::PerSet`] answers the broad one no predicate scores: here is
/// EVERY row you spun off. Its ids come from the recorder's record directly,
/// because a finding is emitted only for a refusal and the checklist is about
/// the whole set.
///
/// # The pointer is the PATH, and that is a stated difference
///
/// The retired shell emitted `<id> filed-over-own-diff <path>` and suppressed on
/// the id. A `Finding` carries its first path-bearing subject as its pointer and
/// the row's id travels as an ordered subject the engine does not project onto
/// the struct, so the nudge names the path and the suppression key is the path.
/// That is the half an agent must act on — *finish it now while the file is
/// open* — and the id is one board read away. Recorded rather than glossed,
/// because it is a real narrowing of what the nudge says.
fn filed_here_pointers(
    overrides: &Overrides,
    root: &Path,
    suppression: Suppression,
) -> Option<String> {
    let config = resolve::resolve(root, overrides).ok()?;
    let only = [FILED_HERE_ROW.to_owned()];
    let (selected, _checks) = select_rules(&config.rules, &only).ok()?;
    let vocabulary = policy::Vocabulary {
        patterns: &config.patterns,
        verdicts: &config.verdicts,
        recorders: &config.recorders,
    };
    let scan = rules::run_static(&selected, &config.provisions, vocabulary, root).ok()?;
    let flagged: std::collections::BTreeSet<String> = scan
        .findings
        .iter()
        .filter(|finding| finding.rule == FILED_OVER_OWN_DIFF)
        .map(|finding| finding.path.clone())
        .collect();
    let git_dir = git::git_dir(root).ok()?;
    let branch = git::current_branch(root).ok()??;
    let lines: Vec<String> = match suppression {
        Suppression::PerRow => flagged.into_iter().collect(),
        Suppression::PerSet => {
            // EVERY ROW, MARKED — the checklist's whole question. A row whose
            // named paths intersect the diff is marked so the reader can see
            // which ones rule 3 already asked about; the rest are `filed`, and
            // the judgement about all of them is the agent's.
            // The same partition the writer used (CLOUD-1300): this checklist is
            // about rows THIS attempt filed, so a previous attempt's rows on a
            // reused branch name are not its business either.
            let claim = claim::claimed_token(&git_dir.join("batten-receipts"), &branch);
            let record = recorder::record_path(&git_dir, BOARD_RECORD, &branch, claim.as_deref());
            let text = std::fs::read_to_string(record).ok()?;
            let mut seen = std::collections::BTreeSet::new();
            text.lines()
                .filter_map(|line| {
                    let mut columns = line.split(' ');
                    (columns.next()? == "issue").then(|| columns.next())?
                })
                .filter(|id| seen.insert((*id).to_owned()))
                .map(|id| format!("{id} filed"))
                .collect()
        }
    };
    if lines.is_empty() {
        return None;
    }
    // THE SUPPRESSION, and its unit is what the two modes disagree about. Rule 3
    // stores one line per row, so a second row is asked about and the first is
    // not; rule 5 stores the whole set as one key, so the list is asked again in
    // full the moment it changes and never partially.
    let (store, keys) = match suppression {
        Suppression::PerRow => (
            git_dir
                .join("batten-receipts")
                .join(format!("filed-here-nudged.{}", branch.replace('/', "-"))),
            lines.clone(),
        ),
        Suppression::PerSet => (
            git_dir
                .join("batten-receipts")
                .join(format!("filed-set-nudged.{}", branch.replace('/', "-"))),
            vec![lines.join(" ")],
        ),
    };
    let already: std::collections::BTreeSet<String> = std::fs::read_to_string(&store)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default();
    let fresh: Vec<String> = keys
        .iter()
        .filter(|key| !already.contains(*key))
        .cloned()
        .collect();
    if fresh.is_empty() {
        return None;
    }
    // Written before the nudge is returned, so a turn that is interrupted after
    // being told still counts as told. Silent on failure, like everything here.
    if let Some(parent) = store.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&store)
    {
        for key in &fresh {
            let _ = writeln!(file, "{key}");
        }
    }
    Some(match suppression {
        Suppression::PerRow => fresh.join("\n"),
        Suppression::PerSet => lines.join("\n"),
    })
}

/// The row the two nudge modes read, and the predicate whose findings rule 3 uses.
const FILED_HERE_ROW: &str = "filed-here";
const FILED_OVER_OWN_DIFF: &str = "filed-over-own-diff";
/// The record the checklist enumerates.
const BOARD_RECORD: &str = "board-writes";

/// Whether a filed-row pointer is suppressed per row or per set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Suppression {
    /// Rule 3: one nudge per row per branch.
    PerRow,
    /// Rule 5: one nudge per SET per branch.
    PerSet,
}

/// Run one sibling program and return its pointer, or `None` for silence.
///
/// The contract is the retired hook's, unchanged: a fired predicate is a
/// non-zero exit with the pointer on stdout, and anything else — clean,
/// unreadable, absent, unrunnable — is silence.
///
/// The spawn itself is [`exec::piped`]'s. This module is not a placed adapter
/// (`policy/spawn-adapters.rego`), and holding its own `Command` here would have
/// been the second copy of a shape the sanctioned boundary already owns.
fn spawn_reading(root: &Path, program: &str, stdin: &str) -> Option<String> {
    let (code, stdout) = exec::piped(root, Path::new(program), &[], stdin)?;
    if code == 0 {
        return None;
    }
    let pointer = stdout.trim_end();
    (!pointer.is_empty()).then(|| pointer.to_owned())
}

/// Append every declared record this result earns (CLOUD-1051).
///
/// [`record_mints`]'s shape deliberately: the same cheap-question-first ordering,
/// the same anchor-not-cwd rule, and the same silence on every failure. What
/// differs is that a recorder may SPAWN — see [`crate::recorder::run_program`]'s
/// inventory row — so the tool match is load-bearing rather than an economy, and
/// it is checked inside `append_all` before any program is reached.
fn write_records(overrides: &Overrides, envelope: &hook::Envelope) {
    // The cheap question first, for `record_mints`' reason: a post-tool event for
    // a tool no row names is nearly every call, and `perf-gate` holds the
    // mediated path to a ratio.
    if envelope.result.is_null() {
        return;
    }
    let Some(result) = facts::payload_in(&envelope.result) else {
        return;
    };
    let Ok((policy, _)) = load_policy(overrides, hook::Harness::ExitCode) else {
        return;
    };
    let recorders = policy.declared_recorders();
    if recorders.is_empty() {
        return;
    }
    // THE ANCHOR, NEVER THE CWD (CLOUD-1024's measured defect, restated here
    // because this is a second writer and would have repeated it): `batten hook`
    // is registered once and then mediates calls from wherever the agent happens
    // to be standing.
    let root = hook_authority_root();
    let Ok(git_dir) = git::git_dir(root) else {
        return;
    };
    let Ok(Some(branch)) = git::current_branch(root) else {
        return;
    };
    let patterns = policy.compiled_patterns();
    // RESOLVED ONCE, AND A FAILURE IS `None` RATHER THAN A RETURN. A consumer
    // declaring no column that asks this authority has no use for a grammar, and
    // refusing to write its records because a vocabulary it never asked for is
    // incomplete would make an unrelated table's gap look like this one's verdict.
    let grammar = ready::Grammar::from_compiled(&patterns).ok();
    let context = crate::recorder::Context {
        result: &result,
        input: &envelope.input,
        programs: policy.declared_programs(),
        patterns: &patterns,
        grammar: grammar.as_ref(),
        root,
        branch: Some(&branch),
    };
    crate::recorder::append_all(
        recorders,
        &git_dir,
        &branch,
        &context,
        rules::selects_tool_name,
        &envelope.raw_tool,
    );
}

/// Mint every receipt this result earns (CLOUD-1024).
///
/// **The forgery this removes and the one it must not add are the same
/// question.** A receipt minted from the result is one the agent cannot author;
/// a receipt minted from a result that did not succeed would be a read receipt
/// for a read that never happened, which is worse than the hand-piped path it
/// replaces. [`crate::mint::satisfied`] is what separates them, and it is checked
/// before anything reaches disk rather than after.
///
/// The clock and the ref resolver are read HERE, at the boundary, for the reason
/// every other clock read in this crate is: `render` stays a pure function of its
/// inputs and so stays testable without a world.
///
/// Every failure is silent, which is [`record_agent_fact`]'s posture verbatim: a
/// hook that cannot record a fact must not become the reason work stops. The gate
/// that reads the receipt simply denies again with the same remedy, which is the
/// safe direction and one the agent can see.
/// The payload a host wrote to a file when it refused to hand over a large result.
///
/// CLOUD-1147. A host may substitute a plain-text notice for an over-limit tool
/// result and write the real bytes to a file it names. `payload_in` then fails to
/// parse — the notice is prose, not JSON — and every mint over that call is
/// skipped silently, which is what left three rows permanently un-updatable: the
/// `issue-read` receipt never minted, and `an-update-owes-a-recent-read` refused
/// with a remedy ("re-read the row") that is the very operation that fails.
///
/// Measured 2026-09-01, on the live host: the envelope's `result` is a STRING
/// (not `null`, so the early return above is not what stops the mint) whose text
/// names an absolute path, and that file holds the complete payload the server
/// returned.
///
/// # This is not CLOUD-691's forgery
///
/// The receipt records what was SEEN. Reading the file recovers exactly the bytes
/// the server sent, so a receipt minted from it attests nothing that was not
/// returned — which is why this is a recovery rather than the field-subset
/// compromise CLOUD-1147 contemplated while it believed the bytes were gone.
///
/// # The bounds, and each is load-bearing
///
/// Only a path a HOST placed in a result it substituted, taken from the notice's
/// own shape — never one a caller supplied. Read ONCE, and only when the ordinary
/// decode already failed, so no clean result pays for this. Everything after is
/// unchanged: the recovered value goes through `payload_in` like any other, and a
/// mint's `requires` still decides, so a spilled file lacking the declared fields
/// mints nothing exactly as today.
///
/// Every failure is silent and returns `None`, matching the mint boundary's own
/// documented posture: the gate that reads the receipt simply denies again.
fn recover_spilled(result: &serde_json::Value) -> Option<serde_json::Value> {
    let text = result.as_str()?;
    let path = facts::spilled_path(text)?;
    let bytes = std::fs::read_to_string(path).ok()?;
    facts::payload_in(&serde_json::from_str(&bytes).ok()?)
}

/// Write every receipt these rows mint from one already-unframed result.
///
/// **ONE minting authority, reached from two boundaries** (CLOUD-1264). The
/// `PostToolUse` hook and `batten mcp call` both file a tool result, and before
/// this only the first minted — so closing the raw read path would have bricked
/// every gate that reads an `issue-read` receipt. A second copy of this loop
/// would be a second authority, free to disagree with the first about
/// `requires`, keying or mode.
///
/// **The clock is read HERE rather than by either caller.** `{now}` is the
/// boundary's own instant, and a parameter would let two callers stamp a
/// receipt differently from the same rows.
///
/// **`tool` is the name the BOUNDARY saw**, and the two boundaries spell it
/// differently: the hook passes the host's `raw_tool` (`mcp__Linear__get_issue`)
/// and dispatch passes the bare method (`get_issue`).
/// [`rules::selects_tool_name`] matches a whole name or a whole final
/// `__`-delimited segment, so a row spelling the segment — the spelling
/// CLOUD-178 already prescribes, because a connector's prefix rotates between
/// registration episodes — mints on both. The consequence stated rather than
/// papered over: a row spelling the FULL name matches the hook path only.
/// Dispatch must not synthesise one, because the server it would name is a
/// config key no host ever emitted.
///
/// `result` is already unframed, and each boundary unwraps with its own
/// authority — [`mcp::payload`] for JSON-RPC content blocks, [`facts::payload_in`]
/// for the harness envelope. Every failure is silent, as the mint boundary has
/// always been: the gate that reads the receipt simply denies again.
fn mint_receipts(
    declared: &[crate::mint::Declared],
    tool: &str,
    result: &serde_json::Value,
    root: &Path,
    grammar: Option<&ready::Grammar>,
) {
    let Ok(git_dir) = git::git_dir(root) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since_epoch| since_epoch.as_secs());
    let resolve = |reference: &str| git::resolve_ref(root, reference).ok().flatten();
    for mint in declared {
        if !rules::selects_tool_name(&mint.tool, tool) {
            continue;
        }
        // The branch is resolved only for a row that asked, which is the same
        // economy `receipt::verdicts` states one channel over: a caller must not
        // pay a git invocation for a question it never asks.
        let filename = match mint.key {
            crate::mint::MintKey::Named => {
                let Some(subject) = crate::mint::subject(mint, result) else {
                    continue;
                };
                format!("{}.{subject}", mint.name)
            }
            crate::mint::MintKey::Branch => {
                let Ok(Some(branch)) = git::current_branch(root) else {
                    continue;
                };
                format!("{}.{}", mint.name, branch.replace('/', "-"))
            }
        };
        // `root` is the ANCHOR the block above resolved, never the cwd — a
        // `{authority:…}` piece reads the workspace version from it, and reading
        // that from wherever the agent happens to be standing is the same defect
        // this function's own header records for every other git question here.
        let Some(record) = crate::mint::render(mint, result, now, &resolve, grammar, root) else {
            continue;
        };
        let path = git_dir.join("batten-receipts").join(filename);
        if let Some(parent) = path.parent()
            && std::fs::create_dir_all(parent).is_err()
        {
            continue;
        }
        let written = match mint.mode {
            crate::mint::MintMode::Replace => std::fs::write(&path, &record),
            crate::mint::MintMode::Append => {
                use std::io::Write as _;
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .and_then(|mut file| file.write_all(record.as_bytes()))
            }
        };
        let _ = written;
    }
}

fn record_mints(overrides: &Overrides, envelope: &hook::Envelope) {
    // Before the config load, the cheap question first: a post-tool event for a
    // tool no row names — which is nearly all of them, now that batten is
    // registered on every surface — must do no config work here. `perf-gate`
    // holds the mediated path to a ratio, and this is the call that would move it.
    if envelope.result.is_null() {
        return;
    }
    // THE ENVELOPE IS THE SHAPE. A connector wraps every response in content
    // blocks, so reading fields off `envelope.result` directly matches nothing in
    // production while passing every fixture, which hands the engine a bare
    // object. `facts::payload_in` is the one authority on that unwrap.
    let Some(result) =
        facts::payload_in(&envelope.result).or_else(|| recover_spilled(&envelope.result))
    else {
        return;
    };
    let Ok((policy, _)) = load_policy(overrides, hook::Harness::ExitCode) else {
        return;
    };
    let declared = policy.declared_mints();
    if declared.is_empty() {
        return;
    }
    // THE ANCHOR, NEVER THE CWD, and this is a measured defect rather than a
    // style choice. The first version resolved every git question against `.`,
    // which passed each fixture — a test harness runs the engine IN the repo —
    // and minted nothing at all against the live host, because `batten hook` is
    // registered once and then mediates calls from wherever the agent happens to
    // be standing. `capture_response` states the same rule one function over and
    // is why the capture store kept working while this wrote nothing.
    let root = hook_authority_root();
    // `write_records`' economy and its three-valued read: a consumer whose
    // `[[pattern]]` table cannot build a grammar has no verdict, so an
    // `{authority:…}` piece records `-` rather than a template failing whole.
    let grammar = ready::Grammar::from_compiled(&policy.compiled_patterns()).ok();
    mint_receipts(
        declared,
        &envelope.raw_tool,
        &result,
        root,
        grammar.as_ref(),
    );
}

/// Persist this post-tool response as a local capture (CLOUD-919).
///
/// **Returns nothing, and that is the failure posture rather than laziness.**
/// CLOUD-917's decision, applied: hook execution continues, the exit code is
/// unchanged and never `2` — a storage failure is not a policy verdict — and the
/// outcome is *recorded and reported* instead of raised. It takes `&mut advice`
/// rather than returning a `Result` for the same reason: a `?` here would cross
/// the fill-and-drain span the advisory buffer lives in, and the one escape that
/// span tolerates is a config failure at exit 3.
///
/// This is deliberately the OPPOSITE posture from [`capture::store`]'s own
/// "never a silent skip" doc, and the surface is the reason. `store` is called by
/// `exec`, where an unrecorded capture is a lie about a command a human asked
/// for. Here it is called on the mediated path, where the non-negotiable is that
/// no Batten failure can block a tool call.
///
/// **No repo root, no capture.** [`hook_authority_root`] falls back to the cwd,
/// so capturing unconditionally would scatter state roots across the filesystem
/// on every post-tool call made anywhere — something nothing in this binary did
/// before. A call from outside a repository records the reason and stores
/// nothing.
///
/// Three outcomes, kept distinct (CLOUD-917): an absent member never reaches
/// here, a present-but-empty one is a real record of zero bytes, and a
/// non-empty one is its bytes at the declared fidelity. The provenance row is
/// what tells the first two apart — one carries a digest, the other a reason id,
/// and they differ in which keys exist rather than in a count.
fn capture_response(
    envelope: &hook::Envelope,
    harness: hook::Harness,
    advice: &mut Vec<advisory::Advice>,
) {
    let mut note = |reason: &str| {
        // Pointer-only: the reason id, never a path and never a byte count that
        // could fingerprint the content. The same id reaches `doctor`.
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Advisory,
            format!("hook.capture.response: {reason}"),
        ));
    };
    // NO FALLBACK TO THE CWD, which is what makes the doc above true: resolving
    // to wherever the agent happens to be standing would mint a state root there
    // on every post-tool call. The anchor rather than `.` for the second half of
    // the same reason (CLOUD-824): every other repository read in `run_hook`
    // resolves through `hook_authority_root`, and a capture written under one
    // root while its budget is read from another is two authorities for one
    // call.
    let Ok(root) = git::repo_root(hook_authority_root()) else {
        note(capture::STATE_ROOT_UNRESOLVED);
        return;
    };
    let decoded = match capture::decode_response(&envelope.result) {
        Ok(decoded) => decoded,
        Err(reason) => {
            note(reason);
            record_absence(&root, envelope, harness, reason, advice);
            return;
        }
    };
    let Ok(stored) = capture::store(&root, capture::Stream::Response, &decoded.bytes) else {
        note(capture::STORE_UNWRITABLE);
        record_absence(&root, envelope, harness, capture::STORE_UNWRITABLE, advice);
        return;
    };
    let row = capture::CallRow {
        order: 0,
        // A host that names no session still gets a row, under a token that says
        // so: dropping the row would make an unnamed session look like no calls,
        // and inventing an id would make two of them look like one.
        session: envelope
            .session
            .clone()
            .unwrap_or_else(|| "unnamed".to_owned()),
        source: "post-tool-member".to_owned(),
        host: harness.as_str().to_owned(),
        tool: envelope.raw_tool.clone(),
        event: hook::Event::PostTool.as_str().to_owned(),
        fidelity: decoded.fidelity.as_str().to_owned(),
        // The clock is read at the boundary, as `record_agent_fact` reads it and
        // for the same reason. It is a fact about the CALL, which is why it may
        // live on this row while the content-addressed blob still refuses one.
        seen_at: Some(receipt::rfc3339_utc(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since_epoch| since_epoch.as_secs()),
        )),
        class: None,
        digest: Some(stored.digest),
        absent: None,
    };
    if capture::record_call(&root, &row).is_err() {
        // THE ONE UNRECORDABLE FAILURE (CLOUD-917 clause 4): the provenance write
        // itself. The advisory is the only channel left, which is why it is not
        // conditional on the row.
        note(capture::STORE_UNWRITABLE);
    }
    // Write-time only, and only for responses. `exec` captures are not
    // candidates, so that consumer's behaviour is byte-identical to before.
    // An `Err` here is a store that could not be READ or REWRITTEN — the bytes
    // are already published and the row is already written, so it is never a
    // budget refusal. `BUDGET_EXHAUSTED` would send a `doctor` reader to the
    // wrong remedy, which is the whole point of a reason id.
    if capture::evict_to_budget(&root, capture_budget().as_ref()).is_err() {
        note(capture::STORE_UNWRITABLE);
    }
}

/// A post-tool call whose host sent no response member.
///
/// The row is the whole deliverable, and it is deliberately NOT an advisory: a
/// host that sends nothing is the surveyed-`Unavailable` case rather than a
/// failure, so pushing a reason id at the operator on every such call would make
/// the ordinary shape of five of six harnesses look like a fault. The record is
/// where it belongs — readable on demand, silent otherwise.
///
/// **No repo root, no row**, for `capture_response`'s reason: resolving to the
/// cwd would mint a state root wherever the agent happens to be standing.
fn record_absent_response(
    envelope: &hook::Envelope,
    harness: hook::Harness,
    advice: &mut Vec<advisory::Advice>,
) {
    let Ok(root) = git::repo_root(hook_authority_root()) else {
        return;
    };
    record_absence(&root, envelope, harness, capture::RESPONSE_ABSENT, advice);
    // THE BOUND APPLIES HERE TOO, and this path needs it more than the capture
    // one does: a host that sends no response appends a row per post-tool call
    // and mints no blob, so nothing else would ever bring the log inside its
    // record bound — and `next_order` scans that log on every later call.
    if capture::evict_to_budget(&root, capture_budget().as_ref()).is_err() {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Advisory,
            format!("hook.capture.response: {}", capture::STORE_UNWRITABLE),
        ));
    }
}

/// Record that a capture did not happen, so "no record" cannot mean "no calls".
fn record_absence(
    root: &Path,
    envelope: &hook::Envelope,
    harness: hook::Harness,
    reason: &'static str,
    advice: &mut Vec<advisory::Advice>,
) {
    let row = capture::CallRow {
        order: 0,
        // A host that names no session still gets a row, under a token that says
        // so: dropping the row would make an unnamed session look like no calls,
        // and inventing an id would make two of them look like one.
        session: envelope
            .session
            .clone()
            .unwrap_or_else(|| "unnamed".to_owned()),
        source: "post-tool-member".to_owned(),
        host: harness.as_str().to_owned(),
        tool: envelope.raw_tool.clone(),
        event: hook::Event::PostTool.as_str().to_owned(),
        fidelity: capture::Fidelity::Unavailable.as_str().to_owned(),
        seen_at: None,
        class: None,
        digest: None,
        absent: Some(reason.to_owned()),
    };
    if capture::record_call(root, &row).is_err() {
        advice.push(advisory::Advice::new(
            severity::AdvisoryTier::Advisory,
            format!("hook.capture.response: {}", capture::STORE_UNWRITABLE),
        ));
    }
}

/// The `[capture]` bound, or `None` when the authority cannot be read.
///
/// Read separately from the policy load below, and deliberately tolerant: a
/// capture must not fail because config did not parse, so an unreadable
/// authority means the engine defaults rather than an error.
fn capture_budget() -> Option<capture::CaptureConfig> {
    let text = std::fs::read_to_string(hook_authority_root().join(config::CONFIG_FILE)).ok()?;
    let parsed: config::Config = toml::from_str(&text).ok()?;
    parsed.capture
}

/// The directory `batten hook` reads its authority from (CLOUD-824).
///
/// **Never the session's cwd on its own.** `load_policy` reads `./batten.toml`
/// with no upward walk, so whichever directory this answers *is* which authority
/// governs a mediated call — and a hook fires wherever the agent happens to be
/// standing. Until this existed the answer came from a `cd` in a shell launcher
/// (`.claude/hooks/batten-hook.sh`, deleted by CLOUD-824): a second repo-root
/// resolver outside the single-implementation gate CLOUD-34 built, and one that
/// asked the *wrong git question*. It took the WORKTREE's toplevel where
/// [`git::repo_root`] answers with the repository's shared root, which in a
/// linked worktree is the **main** checkout. [`git`]'s module doc names both
/// spellings and is the one module allowed to; what matters here is that they
/// differ — measured on a constructed pair, two different directories. So from a
/// linked worktree whose checkout carries no `batten.toml` the launcher landed on
/// `Policy::declaring_nothing` and every mediated call was allowed, silently.
/// That is verbatim the state the launcher's own comment called the `cd` "the
/// whole defence" against.
///
/// **[`anchor`], not a bare [`git::repo_root`], and that is the correction the
/// suite forced.** The first attempt here answered `repo_root` unconditionally,
/// on the reading that CLOUD-34's "stable across worktrees" makes the shared root
/// the only honest answer. Ten hook cases went red and were right to: a directory
/// that carries its own `batten.toml` and happens to sit inside another
/// repository — every fixture under `target/tmp`, and a nested project in real
/// life — had its authority ignored in favour of the outer repository's. What
/// CLOUD-34's invariant governs is per-repository **state**, which lives under
/// the shared dir and is untouched by this. So the rule is the one the crate
/// already has: an authority in this directory answers for it, and otherwise the
/// repository does. Reusing it is also the point — `check` and `hook` disagreeing
/// about which directory is "here" would be a second authority on the question
/// this row exists to give one answer to.
///
/// The §2 fixture still decides correctly under it, which is what makes the reuse
/// legitimate rather than convenient: a linked worktree with no `batten.toml`
/// falls through to the repository's, and so does a subdirectory like
/// `crates/batten` — the case the launcher's `cd` was actually written for.
///
/// **Resolved once per process, and lazily.** Once, because three callers asking
/// the same question would spend three lookups on the hottest path in the binary.
/// Lazily, because a pass-through — a read tool, no command, no writes — reaches
/// no config reader at all, and CLOUD-777's acceptance is that such a call costs
/// no more than the published `noop` figure. [`anchor`] also stats before it
/// spawns, so the ordinary case (a session standing at the root) asks git
/// nothing.
///
/// **A directory this cannot resolve is the cwd, not an error.** `batten hook` is
/// registered once and then mediates every call in whatever directory the agent
/// is in, most of them outside any repository; refusing there would make Batten
/// the reason ordinary work stops (CLOUD-70) — the same fail-open posture the
/// launcher had at this exact point (`|| exit 0`), and [`anchor`]'s own fallback.
fn hook_authority_root() -> &'static Path {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(anchor)
}

fn load_policy(
    overrides: &Overrides,
    harness: hook::Harness,
) -> Result<(hook::Policy, Vec<waiver::Waiver>)> {
    let here = hook_authority_root();
    // THE FLAG IS CONSULTED BEFORE THE FILE (CLOUD-719). The zero-config
    // short-circuit below is correct in its own right — `batten hook` runs in
    // directories that are not Batten repositories, and refusing there would
    // make the hook the reason ordinary work stops (CLOUD-70). What it must not
    // do is answer *first*: under `--config-from` the working file's absence is
    // the MAXIMAL WEAKENING, and a policy declaring nothing is exactly the
    // verdict a branch deleting `batten.toml` was hoping for.
    //
    // This is CLOUD-243's rule on the surface where it bites hardest. There the
    // cost was a report that under-stated; here it is an un-gated write, because
    // `hook` is the pre-tool adjudicator and its verdict is the only thing that
    // stops the call. `resolve` already reads the ref and never touches the
    // working tree when one is named (`resolve::authority`), so consulting the
    // flag is all this needs.
    if overrides.config_from.is_none() && !here.join(config::CONFIG_FILE).exists() {
        return Ok((hook::Policy::declaring_nothing(harness), Vec::new()));
    }
    // The waivers travel beside the policy rather than inside it (CLOUD-610).
    // `Policy` is what `adjudicate` decides against and is resolved without a
    // clock; a waiver is only half a fact until a date is applied to it, so
    // folding the table into `Policy` would put an undecided value in the one
    // structure whose whole point is that everything in it is decided.
    let resolved = resolve::resolve(here, overrides)?;
    let policy =
        hook::Policy::from_resolved(&resolved, harness, here, overrides.config_from.as_deref())?;
    Ok((policy, resolved.waivers))
}

/// Resolve the `exec` output predicates for this run (CLOUD-117).
///
/// **Absent authority declares no patterns, and is not an error** — the same
/// reading [`load_policy`] gives the mediated-call policy, and for the same
/// reason. `batten exec` is a wrapper a caller puts in front of arbitrary
/// commands, most of them in directories that are not Batten repositories;
/// refusing there would make the wrapper the reason ordinary work stops.
///
/// An authority that exists and **cannot be read** propagates. A pattern table
/// nobody could parse is a gate that silently did not run, which is the false
/// green this predicate exists to prevent.
/// `batten exec`: layer the flags over the committed table, then dispatch.
///
/// # Errors
///
/// Returns a [`UsageError`] for an unreadable authority or a `--jobs` value that
/// is not a positive whole number, and whatever [`exec::run_with`] returns
/// otherwise — including the child's own code, as a [`error::Passthrough`].
fn run_exec(
    request: &cli::ExecRequest,
    overrides: &Overrides,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let (patterns, mut settings) = load_exec_settings(overrides)?;
    // §8's precedence, flag over file. The two presentation axes are plain
    // presentation, so a flag setting them weakens nothing; `--tee` and
    // `--continue-on-error` widen, and they widen towards the caller's own
    // terminal rather than towards a gate's verdict — the same reading
    // `--verbose` gets.
    // `--capture-only` is `--tee`'s inverse spelling and loses to it when both
    // are typed, because asking for the bytes is the specific request: a caller
    // who typed both meant the one that says what they want rather than the one
    // that says what they do not.
    settings.tee = if request.tee {
        true
    } else if request.capture_only {
        false
    } else {
        settings.tee
    };
    if let Some(format) = request.format {
        settings.format = format;
    }
    if let Some(style) = request.style {
        settings.style = style;
    }
    if let Some(jobs) = request.jobs.as_ref() {
        // Parsed here rather than by clap so the refusal can say what was wrong
        // with the value. `0` is a width nobody can mean, and reading it as `1`
        // would answer a question the caller did not ask; reading it as
        // "unbounded" would be worse.
        settings.jobs = jobs
            .parse::<usize>()
            .ok()
            .filter(|n| *n > 0)
            .ok_or_else(|| {
                UsageError::raise(format!(
                    "exec: --jobs wants a positive whole number, not `{jobs}`"
                ))
            })?;
    }
    settings.continue_on_error = settings.continue_on_error || request.continue_on_error;
    // The report goes to the ERROR channel, never `out`: stdout belongs to the
    // wrapped command (CLOUD-285), so a pointer line there would corrupt a
    // document the caller may be parsing.
    exec::run_with(&request.command, &patterns, &settings, err)
}

fn load_exec_settings(
    overrides: &Overrides,
) -> Result<(Vec<outputs::OutputPattern>, exec::ExecConfig)> {
    let here = Path::new(".");
    // The flag before the file, for the reason `load_policy` states at length
    // (CLOUD-719). The failure here is quieter than the hook's and still real:
    // deleting `batten.toml` drops every `[[exec_pattern]]` row, so a wrapped
    // command that lies with exit `0` stops being promoted to a failure — the
    // one thing CLOUD-117 built this table to catch.
    if overrides.config_from.is_none() && !here.join(config::CONFIG_FILE).exists() {
        return Ok((Vec::new(), exec::ExecConfig::DEFAULT));
    }
    // One resolve for both, because they are one question — what this repository
    // declared about wrapped commands. Two calls would read the authority twice
    // and could, on a file rewritten in between, answer from two different epochs.
    let config = resolve::resolve(here, overrides)?;
    let settings = config.exec.unwrap_or(exec::ExecConfig::DEFAULT);
    Ok((config.exec_patterns, settings))
}

/// Map one decoded call onto its harness's decision channel.
///
/// Split out of [`run_hook`] so the mapping is reachable without the process's
/// own stdin: `run_hook` owns the boundary (stdin, the bypass variable, the
/// config load) and this owns the contract CLOUD-40's matrix pins — including
/// the case where writing the decision document itself fails.
/// What a refusal line needs to render, resolved by the caller.
///
/// TWO VALUES THAT TRAVEL TOGETHER, and bundling them is what keeps [`render`]'s
/// signature honest rather than merely short: both are resolved from the policy at
/// the boundary, and NEITHER is an input to the decision. The hatch is a name the
/// renderer prints; the ceiling is a bound on how long the printed line may be.
/// Reaching for `policy` inside `render` to fetch either would give it back the
/// inputs CLOUD-898 says it must not have, over values that decide nothing about
/// the call.
///
/// Growing this struct is therefore the test for a third one: it belongs here if
/// the renderer only prints or measures it, and belongs nowhere near here if the
/// renderer would have to branch on it to decide.
struct Rendering<'a> {
    /// The environment variable that suppresses this refusal, by name.
    hatch: &'a str,
    /// What one emitted mediated line may cost, or no declared bound.
    ceiling: Option<&'a refusal::Ceiling>,
}

fn render(
    harness: hook::Harness,
    envelope: &hook::Envelope,
    decision: hook::Decision,
    rendering: &Rendering<'_>,
    mode: Mode,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let Rendering { hatch, ceiling } = *rendering;
    // THE DECISION ARRIVES AS A VALUE, which is what makes this a renderer
    // rather than a second adjudicator (CLOUD-898). A handler's refusal and the
    // engine's own reach the host through the identical match below: a
    // dispatched program must not be able to reach a channel the engine does
    // not, and one rendering path is how that is structural rather than
    // reviewed. It also drops `policy` and `facts` from the signature — a
    // renderer that cannot see the inputs cannot re-decide by accident.
    match decision {
        hook::Decision::Allow => Ok(ExitCode::Success),
        // A suppressed deny (CLOUD-610) is an allow that owes a record, and this
        // is where the record is written — on the ERROR channel, at `Normal`, in
        // the shape the tree side writes at the `waiver::apply` call site. Both
        // choices are the tree side's, taken again rather than re-decided: stderr
        // because a decision document on stdout is what a host parses and an
        // audit line is not part of it, and `Normal` because a policy finding
        // that was let through is not a detail a default run should have to ask
        // for.
        //
        // Pointer-only (non-negotiable rule 4): `Suppressed` carries a rule and
        // an expiry and structurally cannot carry the command, so this call site
        // has nothing to leak even by mistake.
        hook::Decision::Waived(suppressed) => {
            output::message(mode, Verbosity::Normal, err, &suppressed.line_text())?;
            Ok(ExitCode::Success)
        }
        // One dispatch for every host, because the *shape* of the answer is the
        // adapter's business and the decision is not. A host that reads a body
        // gets one; a host whose channel is the exit code alone gets the §7 `2`
        // with the reason on stderr. Adding a host does not touch this function.
        //
        // The host's OWN event spelling goes back, not our normalized token: a
        // decision document is read by the host, which knows only its own
        // vocabulary. Normalizing inward and echoing outward are different
        // directions, which is why the envelope carries both.
        // One refusal value, projected onto whichever channel this host reads
        // (CLOUD-122). The projection happens once, here, so the in-band document
        // and the stderr line cannot disagree about what the refusal said or
        // whether it named a fix.
        hook::Decision::Deny(refusal) => {
            // THE EFFECT IS HERE AND THE RENDERING IS NOT (CLOUD-1386).
            // `deny_text` decides between two projections and stays pure;
            // consulting-and-marking a store is a write, and a write belongs at
            // the boundary with every other one. A renderer that touched the disk
            // would also be one no test could drive twice.
            let first_sighting = refusal
                .verdict()
                .is_none_or(|token| refusal::first_sighting(hook_authority_root(), token));
            let reason = hook::deny_text(&refusal, hatch, first_sighting, ceiling);
            match hook::encode_deny(harness, &envelope.raw_event, &reason)? {
                Some(body) => {
                    writeln!(out, "{body}")?;
                    Ok(ExitCode::Success)
                }
                None => Err(Denial::raise(reason)),
            }
        }
        // The escalation degradation (CLOUD-45 §7(b)), decided in exactly one
        // place. Unreachable until CLOUD-340 lands the `ask` severity that lets a
        // consumer ask for one — stated rather than left to be discovered, and
        // written now so that issue adds a config token and not a decision. Where the host can ask a human, the ask travels on its channel
        // and the call is neither allowed nor refused. Where it cannot, this
        // falls through to the deny arm's contract — the SAME refusal text, the
        // §7 `2`. What it never becomes is an allow: "check with a human"
        // degrading to "go ahead" is the one direction that inverts the policy,
        // and it is why `encode_ask`'s `None` means refuse rather than proceed.
        hook::Decision::Ask(refusal) => {
            // AN ASK IS ALWAYS A FIRST SIGHTING, and it is not an oversight that
            // it does not consult the store. This escalates to a HUMAN, who has
            // read no earlier firing in this session and has no `explain` to run —
            // so withholding the route to save a clause would be spending their
            // attention rather than the model's.
            let reason = hook::deny_text(&refusal, hatch, true, ceiling);
            match hook::encode_ask(harness, &envelope.raw_event, &reason)? {
                Some(body) => {
                    writeln!(out, "{body}")?;
                    Ok(ExitCode::Success)
                }
                None => Err(Denial::raise(reason)),
            }
        }
        // The pre-approval, and it is the mirror image of the arm above it. An
        // unreachable escalation degrades to a REFUSAL, because "ask a human"
        // becoming "go ahead" inverts the policy. An unreachable pre-approval
        // degrades to a plain ALLOW, because "do not prompt" becoming "prompt" is
        // the host's own default — the operator sees a dialogue they would have
        // seen anyway, and nothing was decided that nobody asked for.
        //
        // Which means `None` here is silence rather than an error, and the exit
        // code is the same `0` either way. That symmetry is the whole reason this
        // is a variant and not a flag on `Allow`: the degradation is decided once,
        // here, by the one function that consults the capability table.
        //
        // Nothing in `adjudicate` can produce this value — its gates group it with
        // `Allow` and say why — so reaching this arm means a `[[hook.handler]]`
        // declaring `preapproves` returned an advisory AND the engine's own
        // decision was already an allow. The upgrade is bounded there, not here.
        hook::Decision::Preapproved(reason) => {
            if let Some(body) = hook::encode_preapproval(harness, &envelope.raw_event, &reason)? {
                writeln!(out, "{body}")?;
            }
            Ok(ExitCode::Success)
        }
    }
}

/// One finding as the `-J` data channel renders it (§6).
///
/// Borrowed from the finding rather than owning a copy, and carrying **two**
/// severity fields that are not two sources of truth: `severity` is the
/// committed rule's own rating, and `report` is that rating rendered through the
/// taxonomy table *after* the resolved `fail_on_warning` setting has been
/// applied. A promoted warning is therefore visible as `"severity": "warn"` with
/// `"report": "fail"` — the promoted disposition, derived here at the output
/// boundary and never stored (see [`severity`]'s one-stored-field rule).
///
/// `identity` is the whole [`identity::StoredIdentity`], not a bare fingerprint,
/// so this document joins `state list -J` **key for key** rather than merely
/// agreeing in value — the same `identity.fingerprint` path reads on both. The
/// version rides along because a consumer freezing a fingerprint forever (SARIF's
/// `partialFingerprints`, CLOUD-167) has to know which function minted it.
#[derive(Debug, serde::Serialize)]
struct FindingView<'a> {
    rule: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    severity: RuleSeverity,
    report: severity::ReportLevel,
    /// The finding's minted identity (CLOUD-322).
    ///
    /// Emitted unconditionally. The oracle argument that kept it off this
    /// channel was inherited from the secret class and does not transfer: a
    /// code-anchored fingerprint digests a line of **tracked source**, already
    /// readable by anyone reading the `path:line` beside it, so confirming a
    /// guess about it buys nothing. The secret class cannot leak here however
    /// this path is written, because [`identity::secret_code_fingerprint`] takes
    /// an `IdentityKey` in its signature — a secret-bearing identity cannot be
    /// minted unkeyed at all.
    ///
    /// Withholding it would not remove the need for a stable key on the wire
    /// (drain dedup, worktree hygiene, SARIF); it would move the derivation
    /// elsewhere, which is the second identity a single module exists to prevent.
    identity: &'a identity::StoredIdentity,
}

/// The `-J` payload for one `check`/`enforce` run.
///
/// The resolved setting rides alongside the findings so a consumer can tell a
/// `warn` that was promoted from one that was not without re-deriving the §8
/// chain itself.
#[derive(Debug, serde::Serialize)]
struct CheckReport<'a> {
    fail_on_warning: bool,
    /// The keys the working tree weakened relative to `--config-from`'s ref.
    /// Absent when the run did not name one, so the field's presence says
    /// "a base ref was compared" rather than "nothing was weakened".
    #[serde(skip_serializing_if = "Option::is_none")]
    config_delta: Option<Vec<DeltaView<'a>>>,
    /// The transcript capability's state, when the authority configured one
    /// (CLOUD-95). Absent when no transcript is declared, so the field's presence
    /// says "this repository uses the capability" rather than "it is available" —
    /// the same reading `config_delta` above gives its own absence.
    ///
    /// It rides the DATA channel deliberately. The stderr half is ladder-gated,
    /// so `--silent` would erase the one signal that dependent rules did not run,
    /// and a skipped gate nobody was told about is the false green this engine
    /// exists to catch. `-J` has no `Mode` to consult, so this cannot be silenced.
    #[serde(skip_serializing_if = "Option::is_none")]
    transcript: Option<TranscriptView>,
    findings: Vec<FindingView<'a>>,
    /// The gates a declared `requires_path` held back (CLOUD-125), each with the
    /// requirement it wanted.
    ///
    /// Here as well as on stderr because a machine consumer has no other way to
    /// tell a skip-only run from an all-pass one: both emit no findings and both
    /// exit `0`, so without this field the `-J` documents are byte-identical and
    /// "not rendered as a pass" would be true only of the human channel.
    ///
    /// Omitted when empty, which is what keeps this additive: every run that has
    /// no declared precondition emits exactly the document it emitted before.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    skipped: Vec<SkipView<'a>>,
    /// The gates whose evaluation errored and was contained (CLOUD-126).
    ///
    /// Present for the reason `skipped` is, one severity up: a run that exits
    /// `2` on a violation while some other gate could not be evaluated must let
    /// a consumer see the second fact, because the exit code deliberately
    /// reports only the first.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    errored: Vec<ErrorView<'a>>,
}

/// One gate a declared input-precondition held back, as `-J` renders it.
///
/// Pointer-only by construction: the rule's id and the declared path it wanted.
/// The path is a requirement its own author wrote in the committed authority, so
/// nothing here is read out of the tree.
#[derive(Debug, serde::Serialize)]
struct SkipView<'a> {
    rule: &'a str,
    requires: &'a str,
}

/// One contained failure, as `-J` renders it.
///
/// The class token and nothing else. An error's message may carry file contents
/// or a command's output, so it does not reach this channel at all (rule 4) —
/// which is why the type has no field it could arrive in.
#[derive(Debug, serde::Serialize)]
struct ErrorView<'a> {
    rule: &'a str,
    class: &'static str,
}

/// The transcript capability as the `-J` document renders it: a state token and,
/// when present, counts. Never a pointer into the file's content, and never the
/// configured path — a path is the operator's filesystem, which the data channel
/// has no business carrying.
#[derive(Debug, serde::Serialize)]
struct TranscriptView {
    capability: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    counts: Option<transcript::Counts>,
    /// Unprompted self-persistence (CLOUD-267), as counts and line pointers.
    ///
    /// Advisory and structurally unable to block: it rides the transcript view
    /// rather than the `findings` vec, so no promotion setting and no
    /// `--fail-on-warning` can route it to an exit code (house style §0.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    unprompted_memory_writes: Option<SelfWriteView>,
}

/// The self-persistence scan as the `-J` document renders it.
///
/// Counts plus bare line numbers. Never the memory key, the target path, the
/// tool arguments, or the written bytes — those are what the agent persisted,
/// and disclosing them is the leak the rule exists to avoid.
#[derive(Debug, serde::Serialize)]
struct SelfWriteView {
    #[serde(flatten)]
    counts: selfwrite::Counts,
    #[serde(skip_serializing_if = "Option::is_none")]
    session: Option<String>,
    lines: Vec<usize>,
}

/// One weakened key in the `-J` payload, the same pointer the human channel
/// prints, split into its parts so a consumer need not parse the arrow.
#[derive(Debug, serde::Serialize)]
struct DeltaView<'a> {
    key: &'a str,
    base: &'a str,
    working: &'a str,
}

/// The transcript half of the `-J` document.
///
/// `None` for an unconfigured repository: a config that never mentions the key
/// is not missing anything, so the document carries no key either. An **absent**
/// capability does get a view, because that is the half `--silent` cannot erase
/// and the whole reason the skip is honest.
fn transcript_view(
    capability: &transcript::Capability,
    self_writes: &[selfwrite::Detection],
) -> Option<TranscriptView> {
    match capability {
        transcript::Capability::Unconfigured => None,
        // Both unreadable states render the same SHAPE — no counts, nothing to
        // count — while `as_str()` keeps them different WORDS. That split is the
        // whole point: a reader of the `-J` document must be able to tell a seam
        // that was never wired from data that was damaged, because only the
        // second names something to repair (CLOUD-819).
        transcript::Capability::Absent | transcript::Capability::Unreadable(_) => {
            Some(TranscriptView {
                capability: capability.as_str(),
                counts: None,
                unprompted_memory_writes: None,
            })
        }
        transcript::Capability::Present(stream) => Some(TranscriptView {
            capability: capability.as_str(),
            counts: Some(stream.counts()),
            // Emitted only when there is something to point at, so a clean
            // transcript adds no key rather than an empty one.
            unprompted_memory_writes: (!self_writes.is_empty()).then(|| SelfWriteView {
                counts: selfwrite::counts(self_writes),
                // The session pointer the finding anchors to: an id the host
                // minted, never transcript content.
                session: stream.session.clone(),
                lines: self_writes.iter().map(|found| found.line).collect(),
            }),
        }),
    }
}

/// Scan a resolved transcript capability for unprompted self-persistence.
///
/// Split out of [`run_rules`] to keep that function under the line ceiling, and
/// the split falls on a real seam: this is the whole of CLOUD-267's engine-side
/// entry, so a reader looking for "where does the rule run" finds one place.
///
/// An unconfigured or absent capability yields no detections rather than an
/// error — the rule simply did not run, and `ABSENT_NOTICE` is what says so.
/// Which of the two rule surfaces [`run_rules`] is serving.
///
/// The `runner` fn pointer above already encodes this — `run_static` versus
/// `run_all` — but a fn pointer is not a value you can `match` on, and the judge
/// pass needs to ask. Stated as data rather than compared by address, so the
/// question "may this run spawn a configured command?" has one readable answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Surface {
    /// `check`: declared `read` (§5), so no configured command runs.
    ReadOnly,
    /// `enforce`: unclassified, and the only surface a judge runs on.
    Spawning,
}

/// Run every configured judge row, and register what the judges said.
///
/// **This function returns no [`rules::Finding`], and that is its contract.** A
/// judge outcome goes to the store through [`findings::record_advisory`] and
/// nowhere else, so `any_blocking` never sees one and `--fail-on-warning` has
/// nothing to promote (§0.3, CLOUD-56). The exit code of the run that called
/// this is decided entirely by the deterministic findings beside it.
///
/// The order inside each row is load-bearing and is CLOUD-135's, not this
/// issue's: match the glob, offer the spans to [`judge::assemble`], and let it
/// decide protection **before any byte is read into a payload**. A refusal here
/// is exit 1 — a statement about the invocation, never a policy verdict.
///
/// # Errors
///
/// [`UsageError`] (→ exit `1`) for a judge row with no resolvable command, a
/// program absent from `PATH`, or a payload the boundary refuses.
fn run_judges(
    err: &mut dyn Write,
    mode: Mode,
    config: &resolve::Resolved,
    root: &Path,
) -> Result<Vec<findings::Advisory>> {
    let rows: Vec<&rules::Rule> = config
        .rules
        .iter()
        .filter(|rule| rule.kind == rules::RuleKind::Judge)
        .collect();
    if rows.is_empty() {
        return Ok(Vec::new());
    }

    let protected = rules::PathSet::includes("protected", &config.protected)?;
    let cap = judge::effective_cap(
        config.judge.as_ref().and_then(|j| j.max_payload_bytes),
        None,
    );
    let files = rules::tree_files(root)?;

    let mut raised = Vec::new();
    for rule in rows {
        let argv = judge::argv(&rule.id, config.judge.as_ref())?;
        let Some(glob) = rule.glob.as_deref() else {
            continue;
        };
        let criteria = rule.criteria.clone().unwrap_or_default();
        let matched: Vec<&String> = files
            .iter()
            .filter(|path| rules::glob_match(glob, path))
            .collect();
        // No match is no question: a judge asked about nothing would spend a
        // metered model call to be told so. The glob is a gate before it is a
        // payload source, the same reading `run_rule` gives a command row.
        if matched.is_empty() {
            continue;
        }
        let mut spans = Vec::with_capacity(matched.len());
        for path in &matched {
            spans.push(judge::Span {
                rule: rule.id.clone(),
                path: Some((*path).clone()),
                line: None,
                class: judge::PayloadClass::FileText,
                bytes: std::fs::read(root.join(path)).unwrap_or_default(),
            });
        }
        let rule_text = judge::RuleText {
            id: rule.id.clone(),
            criteria,
        };
        let assembled = judge::assemble(&rule_text, &spans, &protected, config.judge.as_ref(), cap)
            .map_err(|refusal| UsageError::raise(refusal.line()))?;
        let verdict = judge::invoke(&rule.id, &argv, &assembled.serialized)?;
        // The pointer-only invocation record, on the error channel and
        // ladder-gated: it is a statement about Batten's own egress, which a
        // default run should see and a quiet one need not.
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "judge {}: {} bytes to {} over {} file(s) — {}",
                rule.id,
                assembled.record.bytes,
                argv.first().map_or("<none>", String::as_str),
                assembled.record.matched_files,
                verdict.as_str()
            ),
        )?;
        if !verdict.registers() {
            continue;
        }
        raised.push(findings::Advisory {
            rule: rule.id.clone(),
            // A judge finding is a whole-scope condition — the row and the file
            // set it named — so it takes the `scope` identity, the same one a
            // budget or a ledger finding takes. Deliberately NOT the payload
            // hash: that would re-mint the identity every time any matched file
            // changed, so a settled judge finding would reappear as a new one
            // after an unrelated edit, which is the churn CLOUD-123 exists to
            // prevent.
            identity: identity::StoredIdentity::new(
                identity::FindingKind::Scope,
                identity::scope_fingerprint(&rule.id, glob),
            ),
            tier: rule.tier.unwrap_or(severity::AdvisoryTier::Advisory),
            path: glob.to_owned(),
            line: None,
            check: findings::Check::Argv(argv.clone()),
            remediation: findings::Remediation::NoFix(
                rule.no_fix_reason.clone().unwrap_or_default(),
            ),
        });
    }
    Ok(raised)
}

/// Put judge outcomes in the findings store, or say why they are not there.
///
/// Split from [`run_judges`] so the spawn and the persistence are separable: a
/// judge's verdict is a fact about the tree whether or not a store exists to
/// hold it, and folding the two together would make an unopenable store look
/// like a judge that did not run.
///
/// **No failure path here reaches the exit code.** A store that is absent,
/// busy, or newer than this binary reports and returns — the same posture
/// `state record` takes, and a stronger obligation here, because refusing to
/// finish an `enforce` over a *bookkeeping* problem would give an advisory
/// surface the blocking power §0.3 denies it.
///
/// # Errors
///
/// Propagates a write failure on the error channel.
fn register_advisories(raised: &[findings::Advisory], err: &mut dyn Write) -> Result<()> {
    if raised.is_empty() {
        return Ok(());
    }
    let repo = git::repo_root(Path::new("."))?;
    let Some(branch) = git::current_branch(Path::new("."))? else {
        // Detached HEAD names no ref, so there is no context to key an instance
        // on. `state record` raises here; this one reports and carries on, for
        // the reason in the doc comment.
        writeln!(
            err,
            "batten: HEAD is detached, so {} judge finding(s) belong to no ref: persisted:false",
            raised.len()
        )?;
        return Ok(());
    };
    let context = findings::Context::new(format!("refs/heads/{branch}"));
    let commit = git::head_commit(Path::new("."))?;

    let bound = store::commit(store::resolve(&repo)?)?;
    if let Some(note) = &bound.note {
        writeln!(err, "batten: {note}")?;
    }
    let access = journal::open(&bound.dir)?;
    if let journal::Access::DegradedReadOnly { reason, .. } = &access {
        writeln!(err, "batten: degraded read-only: {reason}")?;
        writeln!(
            err,
            "batten: {} judge finding(s): persisted:false",
            raised.len()
        )?;
        return Ok(());
    }
    let schema = access.format().findings_schema;
    let here = std::env::current_dir().ok();
    for advisory in raised {
        findings::record_advisory(
            &bound.dir,
            &context,
            &commit,
            here.as_deref().and_then(Path::to_str),
            advisory,
            schema,
        )?;
    }
    Ok(())
}

/// Put an enforce-surface scan in the findings store, and journal each evaluation
/// it performed (CLOUD-529).
///
/// # Why the call moved and the scan did not
///
/// `batten state record` scans with [`rules::run_static`], so no finding from an
/// enforce-only kind — `command`, and the `secrets` kind — could ever reach the
/// store, and everything downstream of the store (the drain, self-clearing, key
/// custody) was blind to that whole half of the engine. The obvious repair is to
/// widen the recording verb's scan, and it is the wrong one: that verb's own
/// rustdoc refuses it, because a recording verb that could execute a configured
/// command would put user-supplied code behind a store write. So the *journaling*
/// moved to the surface that already spawns instead. `enforce` is already
/// classified `unclassified` for exactly that reason, so this adds no
/// effect-table row and re-classifies nothing, and [`run_state_record`] is
/// untouched.
///
/// # It never mints a store, and that is the drain's posture rather than a
/// recorder's
///
/// [`store::bound_dir`], not [`store::commit`]. `state record` is the declared
/// write half and may mint; a verb whose job is a verdict may not turn a
/// first-ever run into a store creation as a side effect. An unbound store is
/// "not asked", reported at [`Verbosity::Verbose`] and nothing more — the same
/// answer `drain_advisories` gives, for the same reason.
///
/// # No failure path here reaches the exit code
///
/// A detached `HEAD`, an unbound store, a busy merge, a degraded read-only store
/// and a finding the store refuses all report and return. Journaling is a side
/// record of a verdict already reached, so letting any of it move the exit code
/// would make bookkeeping into policy — §5's clause, and the same posture
/// [`register_advisories`] takes one function above.
///
/// # Errors
///
/// Propagates a write failure on the error channel, and a store or journal I/O
/// failure (exit 3, fail loud — never a deny).
fn register_enforce_findings(scan: &rules::Scan, mode: Mode, err: &mut dyn Write) -> Result<()> {
    let repo = git::repo_root(Path::new("."))?;
    let opened = store::resolve(&repo)?;
    let Some(dir) = store::bound_dir(&opened) else {
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            "no bound findings store, so this scan is not journalled",
        )?;
        return Ok(());
    };
    // The ref comes from the process directory, never from `repo`: `repo_root`
    // answers with the MAIN worktree's root, so asking it for the branch would
    // pile every linked worktree's observations onto one context.
    let Some(branch) = git::current_branch(Path::new("."))? else {
        writeln!(
            err,
            "batten: HEAD is detached, so this scan belongs to no ref: persisted:false"
        )?;
        return Ok(());
    };
    let context = findings::Context::new(format!("refs/heads/{branch}"));
    let commit = git::head_commit(Path::new("."))?;

    let access = journal::open(&dir)?;
    if let journal::Access::DegradedReadOnly { reason, .. } = &access {
        writeln!(err, "batten: degraded read-only: {reason}")?;
        writeln!(err, "batten: enforce {context}: persisted:false")?;
        return Ok(());
    }
    let schema = access.format().findings_schema;

    // `record` refuses a finding with no remediation as a usage error, which is
    // the right answer for a recording verb and the wrong one here: it would let
    // one unfixable rule row turn a policy verdict into exit 1. So this reports a
    // count rather than being an `expect`.
    //
    // THE REASON THIS COMMENT USED TO GIVE WAS FALSE, and correcting it is half
    // of CLOUD-1220. It said "`Rule::validate` already refuses such a row, so
    // this partition should never fire". `Rule::validate` refuses no such thing
    // for the one kind it mattered for: `RuleKind::Policy` requires only
    // `severity`, where `RuleKind::Judge` requires `no_fix_reason` outright and
    // says why — a judge finding reaches the store and CLOUD-81's ingest refuses
    // one nothing can close. Policy rows never got that treatment, so the
    // partition fired on EVERY policy-module finding this tree produced and the
    // whole findings subsystem was blind to them.
    //
    // What is true now, and it is a different claim: a policy finding takes its
    // remedy from the `[[verdict]]` class it raises (`policy_remediation`), so
    // the kind that used to fall through no longer can. The partition stays a
    // count rather than an `expect` because a consumer's own registry could
    // still fail to resolve a token this binary did not vendor, and that is a
    // config fault to report rather than a panic — CLOUD-242's lesson is that a
    // guarantee which does not hold is worse than none, so this one is stated as
    // narrowly as it is actually true.
    let (recordable, unrecordable): (Vec<_>, Vec<_>) = scan
        .findings
        .iter()
        .cloned()
        .partition(|finding| finding.remediation.is_some());
    if !unrecordable.is_empty() {
        writeln!(
            err,
            "batten: {} finding(s) carry no remediation: persisted:false",
            unrecordable.len()
        )?;
    }

    let here = std::env::current_dir().ok();
    findings::record(
        &dir,
        &context,
        &commit,
        here.as_deref().and_then(Path::to_str),
        &recordable,
        schema,
        &scan.not_evaluated,
    )?;

    // Custody acts on stored records, which is why it lands here and not in
    // `secrets.rs`: that module holds the keys and must never read the store it
    // protects, and this seam holds the store and never sees a key's bytes.
    reconcile_secret_custody(&repo, &dir, err)?;

    // The worktree actually scanned, not the repository root: `shard_id` is per
    // WORKTREE, and a relative `.` would fingerprint identically from every one of
    // them — collapsing the per-writer shards into one shared file, which is the
    // lock-free concurrency the journal is built on.
    let appended = journal_evaluations(&dir, here.as_deref().unwrap_or(&repo), &context)?;
    if appended > 0 && journal::merge(&dir)? == journal::Merge::Busy {
        writeln!(
            err,
            "batten: shard-merge busy; this scan's evaluations stay queued in this worktree's shard"
        )?;
    }
    output::message(
        mode,
        Verbosity::Verbose,
        err,
        &format!("enforce {context}: {appended} evaluation(s) journalled"),
    )?;
    Ok(())
}

/// Apply what the custody ledger says to the records it is about: move a rotated
/// identity onto its new key, re-open an orphaned one, and close a finished
/// rotation window (CLOUD-529).
///
/// # The split this function is one half of
///
/// `secrets.rs` owns the keys and the ledger and reads **no** store — the
/// invariant the keyed identity rests on is that the key is not reachable from the
/// digests it protects, and a module that opened the store would be one edit away
/// from breaking it. This seam owns the store and never sees a key's bytes. So the
/// span-dependent half (a dual-HMAC pair, computable only while both keys are held)
/// is written to the ledger by the scan, and the record-dependent half is applied
/// from here.
///
/// # Rotation moves a record, it does not re-mint one
///
/// A join names (old fingerprint, new fingerprint) for one span under two
/// generations. Applying it copies the record onto the new identity **carrying its
/// disposition, tier and instances**, and removes the old one. That is the whole
/// point of joining rather than re-scanning into a fresh record: a
/// `rejected-by-design` decision outlives the key it was made under, and a
/// rotation that dropped it would silently resurrect every finding a reviewer had
/// already dismissed.
///
/// # Key loss is the other branch, and it is loud
///
/// A generation the ledger names that the key file no longer holds makes every
/// identity minted under it unreproducible: the span comes back from a re-scan, the
/// old HMAC does not come back without the old key. Those findings are re-opened —
/// returned to unsettled, so the operator re-triages them — and the count is
/// reported. **Never a silent re-mint**: `secrets::read` already refuses to re-mint
/// over a malformed key file, and this is that same refusal at the store boundary,
/// which is where the consequence actually lands.
///
/// # Errors
///
/// Propagates a ledger read, a store read or a record write failure.
fn reconcile_secret_custody(repo: &Path, store_dir: &Path, err: &mut dyn Write) -> Result<()> {
    let today = waiver::today()?;
    let key_file = secrets::key_path(repo)?;
    let ledger = secrets::ledger_path(repo)?;
    // Nothing has ever scanned for a secret here, so there is no custody to
    // reconcile and — this is the load-bearing half — no key to mint either. A
    // reconciliation that minted a key would give every repository a key file for
    // running `enforce` once, and the orphan check's whole premise is that a key
    // file appearing is not the same as a generation existing.
    if !ledger.exists() {
        return Ok(());
    }

    let joined = secrets::joins(&ledger)?;
    let mut moved = 0;
    for (old, new) in &joined {
        if apply_join(store_dir, *old, *new)? {
            moved += 1;
        }
    }
    if moved > 0 {
        writeln!(
            err,
            "batten: secret-identity rotation: {moved} finding(s) re-keyed"
        )?;
    }

    let lost = secrets::orphaned_key_ids(repo, today)?;
    if !lost.is_empty() {
        // Every secret-class record EXCEPT the ones a join has already moved onto a
        // held generation. The exclusion is what keeps the event proportionate, and
        // the breadth of what remains is not a shortcut: the key id lives inside the
        // preimage, so with the key gone there is no way to ask a record which
        // generation minted it. Guessing would be the silent path, and the honest
        // answer to "cannot tell" is to re-triage.
        let reproducible: std::collections::BTreeSet<String> =
            joined.iter().map(|(_, new)| new.to_hex()).collect();
        let mut reopened = 0;
        for mut record in findings::load_all(store_dir)? {
            if !record.identity.is_secret()
                || reproducible.contains(&record.identity.fingerprint.to_hex())
            {
                continue;
            }
            if record.reopen() {
                findings::save_one(store_dir, &record)?;
                reopened += 1;
            }
        }
        for key_id in &lost {
            secrets::record_orphan(&key_file, key_id, reopened)?;
        }
        // On the error channel unconditionally, never ladder-gated: this is the
        // loud event §7(d) asks for, and a custody loss an operator has to opt in
        // to hearing about is one they will not hear about.
        writeln!(
            err,
            "batten: secret-identity key(s) {} are gone: {reopened} finding(s) re-opened for \
             re-triage. Their identities cannot be re-derived, so nothing has been re-minted.",
            lost.join(", ")
        )?;
    }

    // The window closes when nothing is keyed under the retired generation any
    // more — which only this side can see, since it is a fact about records.
    //
    // **The test is over the RECORDS, not over the joins**, and the difference is a
    // window that closes too early. A run whose secrets rule matched nothing
    // journals no pair at all, so "no outstanding joins" is true on the first
    // evaluation after a rotation — and retiring there would drop the old key while
    // records were still keyed under it, which is the orphan this whole branch
    // exists to avoid, reached by the code meant to finish the rotation cleanly.
    // So a secret-class record that is not the new half of a join holds the window
    // open. A cleared-but-still-present record holds it open too, and that is the
    // safe direction: it costs a rotation that cannot start until ref-death GC
    // collects the record, where the other way costs a key.
    if secrets::custody(repo, today)?.retired().is_some() {
        let joined_new: std::collections::BTreeSet<String> =
            joined.iter().map(|(_, new)| new.to_hex()).collect();
        let outstanding = findings::load_all(store_dir)?.into_iter().any(|record| {
            record.identity.is_secret()
                && !joined_new.contains(&record.identity.fingerprint.to_hex())
        });
        if !outstanding && let Some(key_id) = secrets::retire(&key_file)? {
            writeln!(
                err,
                "batten: secret-identity rotation complete: key {key_id} retired"
            )?;
        }
    }
    Ok(())
}

/// Move one record from its pre-rotation identity to its post-rotation one.
///
/// Returns whether anything moved: an already-applied join finds no old record and
/// is a no-op, which is what makes reading the whole ledger every run cheap and
/// safe rather than needing an "applied" marker that could itself be lost.
fn apply_join(
    store_dir: &Path,
    old: identity::Fingerprint,
    new: identity::Fingerprint,
) -> Result<bool> {
    let Some(mut record) = findings::load_one(store_dir, old)? else {
        return Ok(false);
    };
    // The new identity, with everything the old record knew. `tier` travels
    // untouched for CLOUD-80's no-escalation law, and `disposition` travels because
    // a rotation is a change of key, not a change of what a reviewer decided.
    record.identity = identity::StoredIdentity::secret(new);
    findings::save_one(store_dir, &record)?;
    findings::forget(store_dir, old)?;
    Ok(true)
}

/// Journal one evaluation entry per identity this scan spoke about.
///
/// # Read back from the store rather than folded a second time
///
/// [`findings::record`] folds identical spans into one identity with a count
/// inside itself and returns only a summary, so an entry built from the scan
/// would have to repeat that fold — two implementations of "how many
/// occurrences", drifting the moment either changes. Reading the instance back
/// means the journal reports exactly what the store holds, with the store as the
/// single authority.
///
/// # The clear side is the whole point
///
/// An evaluation journal that recorded only raises could never show an
/// oscillation, because half of every oscillation is a clear. `record`'s resolve
/// pass has just written `Observed(0)` for everything this context no longer
/// sees, so reading instances back picks up raises, clears and holds in one pass
/// — which is what makes a flap ratio computable at all (CLOUD-165).
///
/// # The growth this accepts, stated rather than discovered
///
/// One entry per evaluated identity per run is unbounded in a long session, where
/// a disposition entry is written once. That is inherent to an evaluation record:
/// the denominator of a state-change *rate* is every evaluation, including the
/// unchanged ones, so suppressing repeats would remove the denominator. What
/// bounds it is that shards die with their worktree and a generation rotation
/// truncates the log, and that every reader takes a bounded suffix.
///
/// # Errors
///
/// Returns an error when the store cannot be read or a shard cannot be appended.
fn journal_evaluations(
    store_dir: &Path,
    worktree: &Path,
    context: &findings::Context,
) -> Result<usize> {
    let shard = journal::shard_id(worktree);
    let mut appended = 0;
    for record in findings::load_all(store_dir)? {
        let Some(instance) = record.instance(context) else {
            continue;
        };
        journal::append(
            store_dir,
            &shard,
            &journal::Entry {
                identity: record.identity.fingerprint.to_hex(),
                rule: record.rule.clone(),
                origin: journal::Origin::Scan,
                context: Some(context.as_str().to_owned()),
                observation: Some(instance.occurrences),
                // A scan settles nothing and shows nothing: the disposition is the
                // agent's to give, and `presentation` belongs to the drain channel
                // (`journal::Origin::Scan`), which is why `merge` ignores this one.
                disposition: None,
                presentation: findings::Presentation::Shown,
            },
        )?;
        appended += 1;
    }
    Ok(appended)
}

/// Where one observation is being written: the ref it belongs to, the commit
/// that ref was at, and the store that will hold it.
///
/// Grouped rather than passed as four parameters because they travel together
/// and only together — an instance is keyed by context and stamped with the
/// commit, and the schema is the store's own version rather than this binary's
/// (`journal`'s write-old rule). Naming the tuple also keeps
/// [`register_completion`] inside the workspace's argument-count lint without
/// the lint being silenced, which is the honest way past it.
#[derive(Debug, Clone, Copy)]
struct Recording<'a> {
    /// The ref this observation belongs to.
    context: &'a findings::Context,
    /// The commit that ref was at when the scan ran.
    commit: &'a str,
    /// The bound store's directory.
    store_dir: &'a Path,
    /// The record schema **the store is written in**, never [`FINDINGS_SCHEMA`].
    ///
    /// [`FINDINGS_SCHEMA`]: findings::FINDINGS_SCHEMA
    schema: u32,
}

/// Run every detector that reads the completed transcript, and fold what they
/// found into the store (CLOUD-97, CLOUD-98).
///
/// Called from `state record` — the verb that already binds the store, owns the
/// ref context, and is the declared write half — so this costs **no new command
/// and no new effect-table row**. `check` is deliberately untouched: these
/// findings never enter that verb's `findings` vec, which is how "an advisory
/// surface is structurally unable to block" (§0.3) is satisfied here, exactly as
/// [`register_advisories`] satisfies it for a judge.
///
/// The transcript is resolved and parsed **once** for every detector. Not only
/// an economy: the absent notice below is a statement about a capability rather
/// than about a rule, so emitting it per detector would report one fact as
/// several, and two parses of one file are two chances to disagree about it.
///
/// Two of the three silent states are shared by every detector:
///
/// * **Unconfigured** — the repository does not use the transcript input, so
///   nothing is written and nothing is said ([`transcript`]'s absent-is-not-empty
///   law).
/// * **Absent** — configured and unreadable, so no predicate ran. The store is
///   left exactly as it was, which **holds** an open finding rather than
///   clearing it, and the notice is reported for the same reason `check` reports
///   it: a skipped gate that exits `0` in silence is the false green.
///
/// # Errors
///
/// Propagates a write failure, an undecodable transcript, and an unresolvable
/// declared `must_land_on`.
fn register_transcript_detectors(
    repo: &Path,
    recording: &Recording<'_>,
    config: &resolve::Resolved,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let declared = config
        .transcript
        .as_ref()
        .and_then(|declared| declared.path.as_deref());
    let capability = transcript::resolve(Path::new("."), declared);
    let stream = match &capability {
        transcript::Capability::Unconfigured => return Ok(()),
        transcript::Capability::Absent => {
            output::message(mode, Verbosity::Normal, err, transcript::ABSENT_NOTICE)?;
            return Ok(());
        }
        // The same could-not-look answer as absent, plus the pointer that names
        // the line to repair (CLOUD-819). This path already returned `Ok(())`
        // for absent, so recording nothing is the established reading here; what
        // changes is only that a decode failure reaches it instead of raising.
        // Reported through the shared helper, so the two callers cannot drift
        // into wording the same state differently.
        transcript::Capability::Unreadable(_) => {
            report_transcript_capability(&capability, mode, err)?;
            return Ok(());
        }
        transcript::Capability::Present(stream) => stream,
    };
    register_completion(repo, recording, config, declared, stream, mode, err)?;
    register_bypass(recording, declared, stream, mode, err)
}

/// Evaluate the done-but-not-landed predicate and fold its answer into the
/// store (CLOUD-97).
///
/// The one silent state that is this detector's own rather than the
/// capability's: **not signalled** — the session declared no stopping point, so
/// nothing is written, because resolving an open finding on that silence would
/// let a scan of a still-running session clear an incident nobody addressed.
///
/// # Errors
///
/// Propagates a write failure, and an unresolvable declared `must_land_on` —
/// which is a config error the caller owes exit `1`, the reading
/// [`worktree::status`] already gives a target its author named and got wrong.
fn register_completion(
    repo: &Path,
    recording: &Recording<'_>,
    config: &resolve::Resolved,
    declared: Option<&str>,
    stream: &transcript::Stream,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let &Recording {
        context,
        commit,
        store_dir,
        schema,
    } = recording;
    let signal = completion::signal(stream);
    // The landing question is asked only once the session has declared a
    // stopping point. Not an optimisation: an unsignalled session's outcome is
    // already decided, and asking git anyway would let a misconfigured target
    // fail a scan whose verdict never depended on it.
    let landing = match signal {
        None => None,
        Some(_) => match resolve_landing_target(repo, config)? {
            Some(target) => Some((
                git::landing(repo, &target, "HEAD", git::Window::DEFAULT)?,
                target,
            )),
            None => None,
        },
    };
    let outcome = completion::assess(signal, landing.as_ref().map(|(landing, _)| landing));

    let Some(observation) = outcome.observation() else {
        // Not signalled: nothing to write. Reported on the top rung, because a
        // detector that ran and answered "nothing" is a detail rather than news.
        output::message(
            mode,
            Verbosity::Verbose,
            err,
            &format!("completion: {} {context}", outcome.as_str()),
        )?;
        return Ok(());
    };

    let identity = completion::identity(stream.session.as_deref());
    let fingerprint = identity.fingerprint.to_hex();
    let advisory = findings::Advisory {
        rule: completion::RULE_ID.to_owned(),
        identity,
        // The one stored severity axis: answer soon, on a bounded deadline, but
        // the session need not stop for it (CLOUD-80). Unlanded work at a
        // declared stopping point is time-sensitive — the checkout it lives in
        // is not permanent — and is still never a reason to block.
        tier: severity::AdvisoryTier::Caution,
        // A pointer pair: the transcript the operator declared, and the line the
        // marker was on. Never a line of it, and never the session id, which
        // reaches the store only inside the fingerprint above.
        path: declared.unwrap_or_default().to_owned(),
        line: outcome.signal().map(|signal| signal.line),
        // The engine's own next evaluation settles it — which *is* the
        // self-clearing mechanism, so the check names it rather than an argv a
        // caller would have to remember to run.
        check: findings::Check::Reevaluate,
        remediation: findings::Remediation::NoFix(completion::no_fix_reason(
            landing
                .as_ref()
                .map_or(completion::NO_TARGET, |(_, target)| target.as_str()),
        )),
    };
    findings::record_sequence(
        store_dir,
        context,
        commit,
        std::env::current_dir()
            .ok()
            .as_deref()
            .and_then(Path::to_str),
        &advisory,
        observation,
        schema,
    )?;

    // Pointer-only (rule 4): the outcome token, the ref, the identity, and
    // counts. Byte-stable for identical inputs — nothing here carries a clock,
    // a path outside the two the config already names, or a SHA.
    let detail = match &outcome {
        completion::Outcome::Raised {
            signal,
            unaccounted,
        } => format!(
            " {}:{} {} unaccounted, marker {}",
            advisory.path,
            signal.line,
            unaccounted,
            signal.marker.as_str()
        ),
        _ => String::new(),
    };
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!(
            "completion: {} {context} {fingerprint}{detail}",
            outcome.as_str()
        ),
    )?;
    Ok(())
}

/// Register every guardrail bypass the session recorded (CLOUD-98).
///
/// The store side is [`register_completion`]'s exactly — [`bypass::Detection`]
/// is a different predicate over the same substrate, registered through the same
/// door — and the two differences are both properties of the subject rather than
/// choices:
///
/// * **It never clears.** A bypass anchors to an immutable transcript event, so
///   the observation is always positive and never resolves to zero. A clean scan
///   writes nothing rather than a clear, because a later transcript saying
///   nothing about an earlier session's bypass is not evidence the bypass did
///   not happen. It settles by disposition instead (CLOUD-78's three-valued
///   model) — the issue's stated assumption 1, landed as written.
/// * **It carries a tier above the completion rule's.** `Warning` is CLOUD-80's
///   "answer now, before the work continues", which is what an overridden
///   guardrail is. Still structurally unable to block: an [`findings::Advisory`]
///   carries no severity the exit contract can read.
///
/// One finding per bypassed **operation**, so two different operations are two
/// findings and a repeat of one is a count.
///
/// # Errors
///
/// Propagates a write failure.
fn register_bypass(
    recording: &Recording<'_>,
    declared: Option<&str>,
    stream: &transcript::Stream,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    let &Recording {
        context,
        commit,
        store_dir,
        schema,
    } = recording;
    let detections = bypass::scan(stream);
    if detections.is_empty() {
        return Ok(());
    }
    let path = declared.unwrap_or_default();
    let here = std::env::current_dir().ok();
    for detection in &detections {
        let advisory = findings::Advisory {
            rule: bypass::RULE_ID.to_owned(),
            identity: detection.identity.clone(),
            tier: severity::AdvisoryTier::Warning,
            path: path.to_owned(),
            // The refusal's line, so the pointer names where the guardrail
            // spoke; the retry's line rides the report below. Never the command,
            // never the target, never an argument.
            line: Some(detection.denied_line),
            check: findings::Check::Reevaluate,
            remediation: findings::Remediation::NoFix(bypass::no_fix_reason()),
        };
        findings::record_sequence(
            store_dir,
            context,
            commit,
            here.as_deref().and_then(Path::to_str),
            &advisory,
            findings::Observation::Observed(detection.retries),
            schema,
        )?;
        // Pointer-only (rule 4): the ref, the identity, the turn pair, the
        // refusal token and a count.
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!(
                "bypass: raised {context} {} {path}:{}->{} {} retry(ies), refusal {}",
                detection.identity.fingerprint.to_hex(),
                detection.denied_line,
                detection.retry_line,
                detection.retries,
                detection.refusal.as_str()
            ),
        )?;
    }
    Ok(())
}

/// The ref landedness is judged against: the declared key, else the remote's
/// recorded default.
///
/// The same ladder [`worktree::status`] walks, and deliberately the same one
/// rather than a second: `must_land_on` is the one key that names a landing
/// target, and a detector that resolved its own would be a second authority on
/// where work is supposed to go. `None` is "nobody could ask", which the caller
/// reads as not-computable and never as landed.
fn resolve_landing_target(repo: &Path, config: &resolve::Resolved) -> Result<Option<String>> {
    match config.must_land_on.as_deref() {
        Some(declared) => Ok(Some(declared.to_owned())),
        None => git::remote_default_branch(repo),
    }
}

/// The human half of the transcript report, for both states that could not be
/// read (CLOUD-819).
///
/// Ladder-gated, because it is a statement about Batten rather than a verdict —
/// the `-J` field is the half that cannot be silenced. Both states are reported;
/// only the unreadable one has a pointer to add, and `Capability::as_str` is what
/// keeps them different words on the data channel.
///
/// Extracted rather than inlined because `run_rules` sits against the line
/// ceiling `clippy::too_many_lines` enforces, and a reporting decision is a seam
/// worth naming in any case.
///
/// # Errors
///
/// Propagates a write failure on the message channel.
fn report_transcript_capability(
    capability: &transcript::Capability,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    match capability {
        transcript::Capability::Absent => {
            output::message(mode, Verbosity::Normal, err, transcript::ABSENT_NOTICE)?;
        }
        transcript::Capability::Unreadable(pointer) => {
            output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("{} ({pointer})", transcript::UNREADABLE_NOTICE),
            )?;
        }
        transcript::Capability::Unconfigured | transcript::Capability::Present(_) => {}
    }
    Ok(())
}

fn scan_self_writes(
    capability: &transcript::Capability,
    declared: Option<&transcript::TranscriptConfig>,
) -> Vec<selfwrite::Detection> {
    match capability {
        transcript::Capability::Present(stream) => selfwrite::scan(
            stream,
            declared
                .and_then(|config| config.memory_root.as_deref())
                .unwrap_or(selfwrite::DEFAULT_MEMORY_ROOT),
        ),
        // An unreadable transcript joins these two rather than getting an arm of
        // its own: all three mean the stream could not be read, and this function
        // answers only "what did the rule detect". WHY it detected nothing is the
        // notice's job and the `-J` field's, which is where the three stay
        // distinguishable (CLOUD-819).
        transcript::Capability::Unconfigured
        | transcript::Capability::Absent
        | transcript::Capability::Unreadable(_) => Vec::new(),
    }
}

/// The human half of the self-persistence report.
///
/// Pointer-only: counts alone on this channel. Never the memory key, the target,
/// the arguments, or the bytes — those are what the agent persisted, and naming
/// them here would disclose exactly what the rule is watching being written.
///
/// Ladder-gated like every other statement-about-Batten, because the `-J` field
/// is the half that cannot be silenced.
///
/// # Errors
///
/// Propagates a write failure on the error channel.
fn report_self_writes(
    detections: &[selfwrite::Detection],
    mode: Mode,
    err: &mut dyn Write,
) -> Result<()> {
    if detections.is_empty() {
        return Ok(());
    }
    let folded = selfwrite::counts(detections);
    output::message(
        mode,
        Verbosity::Normal,
        err,
        &format!(
            "transcript: {} memory write(s) in a turn no user message opened, {} unresolved",
            folded.raised, folded.unresolved
        ),
    )?;
    Ok(())
}

/// Run the configured rules against the current directory and report findings.
///
/// `runner` selects which surface runs them — [`rules::run_static`] for the
/// `read`-effect `check`, [`rules::run_all`] for the unclassified `enforce`
/// (§5, CLOUD-170). Both report identically; only the admissible rule kinds
/// differ, so the two verbs can never drift in output shape.
///
/// Output is pointer-only (non-negotiable rule 4): one `path:line rule-id` per
/// finding, byte-stable and never the matched bytes. `json` swaps that for the
/// `-J` data channel, which is the same pointers plus each finding's severity
/// and its post-promotion reporting level — still never the matched bytes.
///
/// The exit code consumes each finding's severity (CLOUD-61): a clean run exits
/// [`ExitCode::Success`], any `deny` finding exits [`ExitCode::Violation`], and
/// a `warn` finding is reported without failing the run unless the resolved
/// `fail_on_warning` setting promotes it (CLOUD-49). Reporting is unaffected by
/// that promotion: a warn finding prints either way, and only the verdict moves.
/// The `config deprecations -J` document: what left the surface unannounced.
///
/// THREE-VALUED, and `baseline` is the field that makes it so. An unreadable
/// baseline and a clean comparison would otherwise both render
/// `removed_without_window: []`, so a consumer could not tell "nothing was
/// removed" from "nothing was compared" — CLOUD-251's vacuous pass, moved out of
/// the exit code and into the document a parser actually reads.
#[derive(Debug, serde::Serialize)]
struct DeprecationReport<'a> {
    against: &'a str,
    baseline: &'a str,
    removed_without_window: &'a [String],
}

/// The `config epoch -J` document: the digest and the surface it covers.
#[derive(Debug, serde::Serialize)]
struct EpochReport<'a> {
    epoch: &'a str,
    tracked: &'a [String],
}

/// One smell in the `config lint -J` payload, split into the parts the human
/// pointer line concatenates.
#[derive(Debug, serde::Serialize)]
struct SmellView<'a> {
    at: String,
    id: &'a str,
}

/// The `config lint -J` document. A struct rather than a bare array so the count
/// is a length a consumer can read without a second convention.
#[derive(Debug, serde::Serialize)]
struct LintReport<'a> {
    smells: Vec<SmellView<'a>>,
}

/// Where a rule run is anchored: the process directory when it carries the
/// authority, otherwise the repository root (CLOUD-214).
///
/// A run used to anchor at `.` unconditionally, so `batten check` from a
/// subdirectory reported "no config found at ./batten.toml" and exited on a
/// repository it was standing inside. A pre-commit hook survived that because
/// git runs it at the root; an agent part-way through a trajectory does not, and
/// being unable to run the gate from where you already are is an adoption
/// blocker rather than a nicety.
///
/// **Exactly two candidates are consulted, in this order**, and the order is the
/// whole design:
///
/// 1. **`.`, when it carries a `batten.toml`.** A directory that declares its own
///    authority *is* the subject, whatever it happens to be nested inside. This
///    is what keeps a fixture tree — materialized under `target/`, deep inside
///    this repository — answering about itself rather than about its host, and
///    it makes the common root invocation bit-for-bit what it always was.
/// 2. **The repository root**, via the one `repo_root` primitive. This is the
///    new capability and nothing else: a directory with no authority of its own,
///    inside a repository that has one.
///
/// Absent both, the answer is `.` and `resolve` raises its own "no config"
/// error, naming the file — the same diagnostic as before, from the same place.
///
/// **This is not the upward config walk §8 forbids.** That rule is about
/// *authority*: one committed `batten.toml`, no directory-by-directory probing,
/// no `conf.d` merge. Nothing here probes a chain of parents — it asks git once,
/// for one answer — and nothing merges: exactly one of the two candidates is
/// used, never both. Which is also what makes the output contract hold, since
/// pointers are relative to the anchor and every subdirectory resolves the same
/// one.
fn anchor() -> PathBuf {
    let here = PathBuf::from(".");
    if here.join(config::CONFIG_FILE).is_file() {
        return here;
    }
    git::repo_root(&here).unwrap_or(here)
}

/// Filter `findings` against this checkout's baseline, and fold what drifted
/// back in (CLOUD-67).
///
/// Called from [`run_rules`] immediately before the waiver filter, and that
/// order is load-bearing in one direction: a waiver *removes* a finding, so
/// applying waivers first would make a live baseline entry look unmatched and
/// report staleness for a finding that is still there. Baselining first asks its
/// question of the full set.
///
/// The drift it reports joins `findings` on exactly the terms `budget` and
/// `defects` join on — an unmatched entry is an ordinary [`rules::Finding`], so
/// it is waivable, appears in `-J`, reaches the store and decides the exit code
/// without any of that being re-implemented on a private verdict path.
/// [`baseline::Drifted::is_reportable`] is what keeps a *hold* out of it: an
/// entry whose rule never ran has no verdict to contribute, only a note.
///
/// A checkout with no bound store, or no baseline in it, returns `findings`
/// untouched.
fn apply_baseline(
    findings: Vec<rules::Finding>,
    scan: &rules::Scan,
    root: &Path,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<Vec<rules::Finding>> {
    let Some(recorded) = baseline::load(root)? else {
        return Ok(findings);
    };
    let (mut kept, drifted) = baseline::apply(findings, &recorded, &scan.not_evaluated);
    kept.extend(drifted.iter().filter_map(baseline::Drifted::finding));

    // The audit half, on the ERROR channel beside the waiver lines: a baseline
    // is a suppression, so the record of one is the compensating control, and it
    // must not be able to corrupt a `-J` document even in principle. Holds are
    // reported here and nowhere else — they are exactly the entries that
    // produced no finding, so silence about them would be the whole hold going
    // unobserved.
    for held in drifted.iter().filter(|item| !item.is_reportable()) {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("baseline held {}", held.entry.pointer()),
        )?;
    }
    Ok(kept)
}

/// Drop the findings a spent admission covers, and say which one covered each
/// (CLOUD-1120).
///
/// # The gap this closes
///
/// `override request` articulated, `override spend` consumed, and the gate went
/// on refusing — because `admission::` was reached only by those two verbs and
/// nothing on the evaluation path ever asked. Measured: a `spent` record whose
/// rule, class, subject and HEAD all equalled the refusal's, against a class
/// declaring four routes of which none was reachable. CLOUD-1050 made a remedy
/// checkable; this is what makes one of them *work*.
///
/// # Why the report is not optional
///
/// A suppressed finding is announced on the error channel beside the baseline
/// and waiver lines, naming the admission that covered it. Silence would make an
/// override indistinguishable from a clean tree, which is exactly the property
/// the record was introduced to buy back from a bypass variable — the whole
/// argument for admissions is that an override becomes observable, and a
/// suppression nobody can trace to its reasoning is the variable again.
///
/// # Where it runs, and why between the other two
///
/// After the baseline and before the waiver. A baseline is a recorded backlog
/// and a waiver is a standing exemption; an admission is spent against ONE
/// finding at ONE head. Running after the baseline means a finding the baseline
/// already holds is never charged an admission. Running before the waiver means
/// a standing exemption still wins, so an override is never the cheaper route to
/// something already waived.
///
/// # Fail-closed on everything it cannot establish
///
/// No class for the finding (every native refusal, every consumer `[[rule]]`
/// row) admits nothing — there is no token an admission could bind. An
/// unresolvable HEAD or epoch admits nothing. An unreadable store admits
/// nothing. A store this cannot read must not be able to suppress.
fn apply_admissions(
    findings: Vec<rules::Finding>,
    scan: &rules::Scan,
    root: &Path,
    config_from: Option<&str>,
    mode: Mode,
    err: &mut dyn Write,
) -> Result<Vec<rules::Finding>> {
    // Nothing to admit against: skip the two resolutions rather than paying for
    // them on every clean run.
    if scan.classes.is_empty() || findings.is_empty() {
        return Ok(findings);
    }
    // COULD NOT LOOK ADMITS NOTHING. Both are resolved exactly as `override
    // request` and `override spend` resolve them, because an admission binds the
    // values those verbs saw and a third spelling here could only disagree.
    let (Ok(head), Ok((epoch, _))) = (git::head_commit(root), epoch::describe(root, config_from))
    else {
        return Ok(findings);
    };

    let mut kept = Vec::with_capacity(findings.len());
    for finding in findings {
        let fingerprint = finding.identity.fingerprint.to_hex();
        let Some(class) = scan.classes.get(&fingerprint) else {
            kept.push(finding);
            continue;
        };
        let admitted =
            admission::admitted(root, &finding.rule, class, &finding.path, &head, &epoch)?;
        match admitted {
            Some(address) => output::message(
                mode,
                Verbosity::Normal,
                err,
                &format!("admitted {} {class} {address}", finding.path),
            )?,
            None => kept.push(finding),
        }
    }
    Ok(kept)
}

/// One of the two rule-running surfaces, as [`run_rules`] takes it.
///
/// Named rather than written inline because the pattern table joined the
/// argument list (CLOUD-885) and a four-argument fn pointer is past what
/// `clippy::type_complexity` will read. The alias is also the clearer spelling:
/// the tables and the root are what a runner needs, and saying so once beats
/// repeating it at both call sites.
///
/// The pattern table and the refusal vocabulary travel as one
/// [`policy::Vocabulary`] (CLOUD-1050) rather than as two positions, which is
/// why this alias did not have to grow again.
/// What `check`'s scoping flags asked for, before the repository is consulted
/// (CLOUD-519).
///
/// Two stages, because they need different things. WHICH scope was asked for is
/// decidable from argv alone, and refusing a contradictory pair must happen
/// before any work. WHICH PATHS it names needs the anchored root, so it is
/// [`CheckScope::resolve`]'s job and happens once, inside `run_rules`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckScope<'a> {
    /// No flag: every file the walk yields.
    Tree,
    /// `--staged`.
    Staged,
    /// `--since <rev>`.
    Since(&'a str),
}

impl<'a> CheckScope<'a> {
    /// Which scope the flags name, refusing the pair that names two.
    ///
    /// The mutual exclusion is enforced here rather than by `clap`, because
    /// `surface::FlagDecl` has no conflict column and adding one to express a
    /// constraint that appears on a single verb would widen the spec — and the
    /// schema derived from it — for every row that does not need it. The caller
    /// sees the same exit `1` either way.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (exit `1`) when both flags are passed.
    fn of(staged: bool, since: Option<&'a str>) -> Result<CheckScope<'a>> {
        match (staged, since) {
            (true, Some(_)) => Err(UsageError::raise(
                "check: --staged and --since name two different change-sets; pass one".to_owned(),
            )),
            (true, None) => Ok(CheckScope::Staged),
            (false, Some(rev)) => Ok(CheckScope::Since(rev)),
            (false, None) => Ok(CheckScope::Tree),
        }
    }

    /// The paths this scope names, read through the crate's one git invoker.
    ///
    /// **An unresolvable rev is a usage error, never an empty scope.** A
    /// narrowing that matched nothing and exited `0` is the vacuous pass in its
    /// purest form — the caller reads "the gate passed" from a gate that scanned
    /// no file — which is the same reasoning `surface::CHECK_RULE` states for a
    /// `--rule` naming no declared row, and `git::count_at_rev`'s for a ratchet
    /// base that will not resolve.
    ///
    /// # Errors
    ///
    /// A [`UsageError`] (exit `1`) when the rev does not resolve, or when the
    /// working directory is not a repository whose index and `HEAD` can be read.
    fn resolve(self, root: &Path) -> Result<rules::Scope> {
        match self {
            CheckScope::Tree => Ok(rules::Scope::Tree),
            CheckScope::Staged => Ok(rules::Scope::Changed(git::staged_paths(root)?)),
            CheckScope::Since(rev) => {
                if git::resolve_ref(root, rev)?.is_none() {
                    return Err(UsageError::raise(format!(
                        "check: --since {rev} does not resolve to a commit"
                    )));
                }
                // `base_delta` is the crate's one answer to "what did this branch
                // change against a ref" (§1: never a second git invoker, and
                // never a second opinion). `**` because the scope is the whole
                // tree — the flag narrows which files rules SEE, and a glob here
                // would be a second selection layered under `PathSet`'s.
                let whole_tree = ["**".to_owned()];
                let delta = git::base_delta(root, rev, &whole_tree)?.ok_or_else(|| {
                    UsageError::raise(format!(
                        "check: --since {rev} resolves but its change-set could not be read"
                    ))
                })?;
                // Deleted paths are folded in and cost nothing: the scope is
                // intersected with the walk, so a path that is gone drops out
                // there. Including them keeps this "what changed" rather than
                // "what changed and still exists", which is a different question
                // nobody asked.
                let changed = delta
                    .added
                    .into_iter()
                    .chain(delta.edited)
                    .chain(delta.deleted)
                    .collect();
                Ok(rules::Scope::Changed(changed))
            }
        }
    }
}

/// `check`'s dispatch, extracted so [`run`]'s match stays inside its line budget.
///
/// It exists to hold the one thing `check` does that no other verb does: turn two
/// mutually-exclusive flags into a scope before any work starts.
///
/// # Errors
///
/// As [`run_rules`], plus the two [`CheckScope`] refusals: both flags at once,
/// and a `--since` rev that does not resolve.
fn run_check(
    flags: &cli::CheckFlags,
    mode: Mode,
    overrides: &Overrides,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<ExitCode> {
    let requested = CheckScope::of(flags.staged, flags.since.as_deref())?;
    run_rules(
        out,
        err,
        mode,
        overrides,
        rules::run_static_over,
        RunRequest::read_only(flags.json, &flags.rule, requested),
    )
}

/// The clock a declared `max_age` is read against: `--instant`'s value when the
/// caller named one, and the boundary's own clock otherwise (CLOUD-1170).
///
/// **The fallback is the whole reason this returns a `SystemTime` rather than an
/// `Option`.** One place decides what "no flag" means, so no call site can
/// accidentally decide differently — and what it means is *exactly what it meant
/// before this flag existed*. `Rule::max_age`'s own doc takes the same care in
/// the same words: absent means what it always meant, so no committed row changes
/// meaning by a column arriving.
///
/// **A value that will not parse is a USAGE ERROR, never a silent fallback.**
/// Those are opposite claims. Degrading a typo to "read the clock" would hand
/// back a verdict the caller believes is reproducible and is not — the failure is
/// invisible precisely because the answer still looks right. `--rule` and
/// `--since` both refuse rather than degrade, for this reason; so does this.
///
/// Negative values parse. An epoch second before 1970 is not a lease anybody
/// holds, but refusing it here would be this function inventing a policy about
/// what an instant may MEAN, where its whole job is deciding whether the caller
/// supplied an integer. What the instant means is the declaring row's question.
fn supplied_instant(raw: Option<&str>) -> Result<std::time::SystemTime> {
    let Some(raw) = raw else {
        return Ok(std::time::SystemTime::now());
    };
    let seconds: i64 = raw.trim().parse().map_err(|_| {
        UsageError::raise(format!(
            "hook: --instant takes an epoch second as an integer, and {raw:?} is not one. \
             The caller reads the clock and hands the value in — `--instant \"$(date -u +%s)\"` \
             — so a declared `max_age` is compared against a value a fixture can pin \
             (CLOUD-1170)."
        ))
    })?;
    // Split on the sign rather than casting: `Duration` is unsigned, so a
    // pre-epoch instant is a subtraction from the epoch and not a very large
    // addition to it. Saturating on an absurd value keeps this total — the clock
    // is the caller's claim, and refusing arithmetic over it here would be a
    // second policy about what an instant may mean.
    let magnitude = std::time::Duration::from_secs(seconds.unsigned_abs());
    let resolved = if seconds < 0 {
        std::time::UNIX_EPOCH.checked_sub(magnitude)
    } else {
        std::time::UNIX_EPOCH.checked_add(magnitude)
    };
    Ok(resolved.unwrap_or(std::time::UNIX_EPOCH))
}

type RuleRunner = fn(
    &[rules::Rule],
    &[provision::Provision],
    policy::Vocabulary<'_>,
    &Path,
    rules::RunOptions<'_>,
) -> Result<rules::Scan>;

/// Write what the decision asked for, on the surface allowed to write
/// (CLOUD-851).
///
/// ONLY THE SPAWNING SURFACE. `check` is declared `read` (§5) and computes
/// `scan.requested` exactly as `enforce` does — the decision is the same
/// decision, which is what makes the split a boundary rather than a second
/// engine — but it writes nothing, because a read-effect verb that left a record
/// behind would be a verb that changes what it is judging.
///
/// EVERY FAILURE IS COULD-NOT-RECORD, never a verdict. The run has already
/// decided by the time this is called; a store that cannot be written must not
/// become the reason work stops, which is the same posture `record_sourced`'s
/// caller takes one channel over. Nothing here reaches a stream: the records are
/// digests and counts, and even those stay on disk.
fn perform_requested_sinks(surface: Surface, root: &Path, scan: &rules::Scan) {
    if surface != Surface::Spawning || scan.requested.is_empty() {
        return;
    }
    let Ok(git_dir) = git::git_dir(root) else {
        return;
    };
    // Only when a request needs it, for the reason `rules::run`'s acquisition
    // guard states: a read nobody asked for is what `perf-compare` refused.
    let branch = if scan
        .requested
        .iter()
        .any(|request| request.key == rules::SinkKey::Branch)
    {
        git::current_branch(root).ok().flatten()
    } else {
        None
    };
    let _ = sink::perform(&git_dir, branch.as_deref(), &scan.requested);
}

/// What a rule-running verb was asked for, as one value.
///
/// A struct rather than three more positionals, for `ExecRequest`'s reason and a
/// lint that enforces it: [`run_rules`] is the funnel every rule-running verb
/// comes through, and a funnel that takes eight arguments is one a caller gets
/// wrong by transposing two of them.
#[derive(Debug, Clone, Copy)]
struct RunRequest<'a> {
    /// Which effect class the caller is on, which decides the sink pass.
    surface: Surface,
    /// Emit findings as byte-stable JSON instead of pointer lines.
    json: bool,
    /// Run only the declared row with this id (CLOUD-1051), or every applicable
    /// row.
    only: &'a [String],
    /// Which files the run selects rules against (CLOUD-519), as ASKED FOR — the
    /// git read that resolves it needs the repository root, which is anchored
    /// inside `run_rules`.
    ///
    /// Beside `only` because they are the two narrowings a caller may ask for,
    /// and orthogonal: `--rule` narrows WHICH ROWS run, this narrows WHICH FILES
    /// they are selected against.
    scope: CheckScope<'a>,
}

impl<'a> RunRequest<'a> {
    /// `check`'s request: the read-only surface, optionally narrowed.
    const fn read_only(json: bool, only: &'a [String], scope: CheckScope<'a>) -> RunRequest<'a> {
        RunRequest {
            surface: Surface::ReadOnly,
            json,
            only,
            scope,
        }
    }

    /// `enforce`'s request, narrowable since 2026-09-01.
    ///
    /// THIS REVERSES A RECORDED DECISION AND THE CONDITION IT NAMED HAS FAILED.
    /// This doc said `enforce` was "deliberately NOT narrowable", because
    /// "every caller that needs it is a `check` caller" and offering it here
    /// "would be surface nobody asked for, on the verb that spawns". Both halves
    /// were true when written. The second is not any more.
    ///
    /// The caller is a case whose SUBJECT is a spawning row:
    /// `the_committed_delegating_rule_spawns_nothing_when_its_glob_misses`
    /// asserts that a `kind = "command"` row whose glob misses spawns nothing.
    /// `check` must refuse that by construction, so the case cannot take the
    /// read-surface narrowing, and without one it evaluates all 103 rows to
    /// assert one — 206s of a 1482s suite on the Windows runner, which is the
    /// critical path and bills at 2x.
    ///
    /// So this is not surface nobody asked for. It is the one shape the original
    /// reasoning could not have covered, since a case about a spawning row is
    /// exactly the case that cannot migrate to `check`.
    ///
    /// `enforce` is still not SCOPABLE, and that half stands unchanged: `--staged`
    /// and `--since` are `check`'s, and no caller asks to spawn over a narrowed
    /// file set. Narrowing WHICH ROWS run and narrowing WHICH FILES they select
    /// against are orthogonal, and only the first has a caller here.
    const fn spawning(json: bool, only: &'a [String]) -> RunRequest<'a> {
        RunRequest {
            surface: Surface::Spawning,
            json,
            only,
            scope: CheckScope::Tree,
        }
    }
}

/// The rows a run evaluates, and which config-fault checks it may make.
///
/// # A narrowing narrows BOTH, and two wrong turns settled that
///
/// Loading a one-row subset under the ordinary checks reports every OTHER
/// module's classes as unemitted and refuses — measured the first time `--rule`
/// ran, twenty-six tokens named and none of them the caller's business — because
/// registry equality is a property of the AUTHORITY rather than of a run.
/// Loading the FULL set instead refuses too, for the opposite reason: `check`
/// declines before any work when any declared row spawns, and this repository
/// declares one, so a narrowed read of a policy row died on `no-secrets`.
///
/// So [`policy::ModuleChecks::RunOverSelection`] keeps every check that is about
/// the modules that loaded and drops the one that is about the table, which the
/// unnarrowed run every `verify` performs still answers.
///
/// **A filter matching nothing is a usage error, never a clean run.** That is the
/// vacuous pass in its purest form — the caller reads "the gate passed" from a
/// gate that was never selected, and a renamed row silently stops being
/// enforced.
///
/// # Errors
///
/// Returns a [`error::UsageError`] when any entry of `only` names no declared row.
///
/// **The refusal is PER ID rather than over the set** (CLOUD-1358), and that is
/// the whole reason the repeatable form is safe. Asking "did the selection match
/// anything" would let a typo ride along with a valid sibling: `--rule
/// no-consumer-account-literal --rule no-consumer-acount-path` selects one row,
/// runs, and passes, having silently stopped enforcing the row the caller
/// misspelled. That is the vacuous pass this function exists to refuse, arriving
/// through the door the arity opened, so every named id must match on its own.
fn select_rules(
    declared: &[rules::Rule],
    only: &[String],
) -> Result<(Vec<rules::Rule>, policy::ModuleChecks)> {
    if only.is_empty() {
        return Ok((declared.to_vec(), policy::ModuleChecks::Run));
    }
    let unmatched: Vec<&str> = only
        .iter()
        .map(String::as_str)
        .filter(|id| !declared.iter().any(|rule| rule.id == *id))
        .collect();
    if let Some(first) = unmatched.first() {
        return Err(error::UsageError::raise(format!(
            "no `[[rule]]` row is declared with id `{first}`; this authority declares {} row(s)",
            declared.len()
        )));
    }
    // Declaration order, never the order the flags were written: findings sort by
    // the `(path, line, rule)` pointer tuple downstream, and a selection that
    // reordered the table would make a caller's argv order visible in bytes §6
    // holds stable.
    let selected: Vec<rules::Rule> = declared
        .iter()
        .filter(|rule| only.contains(&rule.id))
        .cloned()
        .collect();
    Ok((selected, policy::ModuleChecks::RunOverSelection))
}

/// The gates the ENGINE owns rather than a `[[rule]]` row, as findings.
///
/// Both join the ordinary finding list, deliberately: a budget and a ledger
/// verdict are policy verdicts like any other, so they must be waivable, must
/// appear in `-J`, and must reach the store — all of which come free from being
/// an ordinary `Finding`, and all of which a private verdict path would have had
/// to re-implement. An over-budget set was previously visible only to whoever
/// thought to run `policy budget`, which is a report, not a gate (CLOUD-50).
///
/// The ledger's gate (CLOUD-52) is engine-side for a sharper reason: it records
/// the lessons that produced the other gates, and one a branch could lower by
/// editing a rule table is worth less than none.
///
/// Rooted at the repo rather than the process directory — the ledger path is
/// repo-relative and the git bases are the repository's, so answering from a
/// subdirectory would read a ledger that is not there. It takes the run's one
/// anchor (CLOUD-214) rather than resolving a second.
///
/// # Errors
///
/// Returns an error when a declared budget entry or the ledger cannot be read.
fn engine_side_findings(root: &Path, config: &resolve::Resolved) -> Result<Vec<rules::Finding>> {
    let mut found: Vec<rules::Finding> = budget::measure_all(root, config.budget.as_ref())?
        .iter()
        .filter_map(budget::Report::finding)
        .collect();
    found.extend(ledger_findings(root, config)?);
    Ok(found)
}

/// The defect-ledger gate alone, split out from its budget sibling (CLOUD-1186).
///
/// **Separate because the two have different standing under a narrowing.** The
/// budget measures declared instruction files — a property of the tree that a
/// caller asking about one rule did not ask about — so a narrowed run skips it on
/// either surface. The ledger is a claim about THIS BRANCH's conduct, and it is
/// engine-side rather than a `[[rule]]` row exactly so a branch cannot lower it
/// by editing a rule table. A narrowing that dropped it on the spawning surface
/// would restore the lowering the placement exists to prevent, in one token.
///
/// # Errors
///
/// Returns an error when the declared ledger cannot be read.
fn ledger_findings(root: &Path, config: &resolve::Resolved) -> Result<Vec<rules::Finding>> {
    match config.defects.as_ref() {
        Some(declared) => defects::gate(root, declared),
        None => Ok(Vec::new()),
    }
}

/// The two stderr notices every rule-running verb opens with.
///
/// Lifted out of [`run_rules`] to keep that funnel under the line lint, and the
/// pair travels together because both are ladder-gated messages about the
/// CONFIG rather than about the tree — stdout is the findings channel and must
/// stay byte-identical to a run whose committed authority states the same
/// effective config, so neither can ever be anything but a stderr line.
///
/// The first is zero-config onboarding's one visible half (CLOUD-70), emitted
/// from this funnel because it is the surface a first contact reaches; `config
/// show` already says the same thing in its own language, by attributing every
/// key to `default`.
///
/// # Errors
///
/// Returns an error when the message channel cannot be written.
fn announce_config(mode: Mode, err: &mut dyn Write, config: &resolve::Resolved) -> Result<()> {
    if config.authority == config::Authority::Absent {
        output::message(mode, Verbosity::Normal, err, config::DEFAULTS_NOTE)?;
    }
    announce_degrade(mode, err, config.base.as_ref())
}

/// Report what each rule cost, on the `-vv` rung (CLOUD-1217).
///
/// **This exists because the largest item in this repository's CI was a silent
/// span.** `batten-check` ran 465s of a 1327s job and emitted two lines, so the
/// cost was unattributable from its own output; two sessions guessed at it and
/// both were wrong, and the answer only came out of a scratch worktree with the
/// ruleset hand-edited. This turns that bisect into a flag.
///
/// **`Debug`, not `Verbose`, and never the answer channel.** A duration is not
/// byte-stable, so it must not reach `-J`, a pointer line or stdout — house-style
/// §6. It is a measurement about the run, not a finding about the tree, and the
/// two channels stay separate.
///
/// Read from `rules::rule_costs()` rather than off the `Scan`: a census is a
/// measurement ABOUT a run, not part of its value, and `batten semver check`
/// refused the field on that public struct — correctly, and the refusal named the
/// design as well as the API. Read immediately after the runner returns, because
/// the store holds the run that just finished.
///
/// Sorted by cost descending, ties broken by rule id, because the question this
/// answers is "what is the pole" and a reader should not have to sort 84 lines.
/// The tiebreak is what keeps two runs over one tree reading the same.
///
/// Pointer-only (non-negotiable rule 4): an id, two counts and a duration. Never
/// a path, never a scanned byte.
fn report_rule_costs(mode: Mode, err: &mut dyn Write) -> Result<()> {
    let costs = rules::rule_costs();
    if costs.is_empty() {
        return Ok(());
    }
    let mut ranked: Vec<&rules::RuleCost> = costs.iter().collect();
    ranked.sort_by(|a, b| {
        b.elapsed
            .cmp(&a.elapsed)
            .then_with(|| a.rule.as_str().cmp(b.rule.as_str()))
    });
    for cost in &ranked {
        output::message(
            mode,
            Verbosity::Debug,
            err,
            &format!(
                "rule cost: {} {}ms {} file(s) {} byte(s)",
                cost.rule,
                cost.elapsed.as_millis(),
                cost.files_read,
                cost.bytes_read
            ),
        )?;
    }
    let elapsed: std::time::Duration = costs.iter().map(|cost| cost.elapsed).sum();
    let files: usize = costs.iter().map(|cost| cost.files_read).sum();
    let bytes: usize = costs.iter().map(|cost| cost.bytes_read).sum();
    output::message(
        mode,
        Verbosity::Debug,
        err,
        &format!(
            "rule cost: {} rule(s) {}ms {files} file(s) {bytes} byte(s)",
            costs.len(),
            elapsed.as_millis(),
        ),
    )?;
    Ok(())
}

#[expect(
    clippy::too_many_lines,
    reason = "the one funnel `check` and `enforce` share, and it reads as one sequence: \
              resolve the config, run the rules, perform the sinks, fold in budgets, \
              filter admissions and waivers, emit, and decide. Splitting it would thread \
              `config`, `root`, `scan` and `findings` through helpers that exist only to \
              satisfy a line count — doctor::diagnose_harness's reason, one funnel over"
)]
fn run_rules(
    out: &mut dyn Write,
    err: &mut dyn Write,
    mode: Mode,
    overrides: &Overrides,
    runner: RuleRunner,
    request: RunRequest<'_>,
) -> Result<ExitCode> {
    let RunRequest {
        surface,
        json,
        only,
        scope,
    } = request;
    // The *resolved* rule set, so a local override's added rules are gates a run
    // actually applies rather than config the tool merely prints. The promotion
    // setting comes off the same resolution, so one §8 chain decides both.
    let base_ref = overrides.config_from.as_deref();
    // One anchor for the whole run, resolved once (CLOUD-214): config, the tree
    // walk, budgets, the ledger and the transcript all answer about the same
    // directory, so a subdirectory invocation cannot read policy from one place
    // and files from another.
    let root = anchor();
    let config = resolve::resolve(&root, overrides)?;
    announce_config(mode, err, &config)?;
    // The whole `Scan`, not just its findings: `not_evaluated` is what keeps the
    // store's resolve pass fail-closed (CLOUD-81), and the enforce surface now
    // journals (CLOUD-529), so dropping it here would let a rule that never
    // looked resolve every finding it covers.
    let vocabulary = policy::Vocabulary {
        patterns: &config.patterns,
        verdicts: &config.verdicts,
        recorders: &config.recorders,
    };
    let (selected, checks) = select_rules(&config.rules, only)?;
    let scope = scope.resolve(&root)?;
    let opts = rules::RunOptions {
        checks,
        scope: &scope,
        // The BOUNDARY's clock, read here and handed over, because `rules.rs`
        // holds the projection and may read none (CLOUD-1170's stated division,
        // gated by `the_evaluation_path_reads_no_wall_clock`).
        now: Some(now_unix()),
    };
    let scan = runner(&selected, &config.provisions, vocabulary, &root, opts)?;
    report_rule_costs(mode, err)?;
    perform_requested_sinks(surface, &root, &scan);
    let mut findings = scan.findings.clone();

    // Declared budgets are gates, evaluated here rather than only under `policy
    // budget` (CLOUD-50). Reading files and summing them spawns nothing, so this
    // preserves `check`'s declared `read` effect.
    //
    // They join `findings` BEFORE the waiver filter below, deliberately: a
    // budget is a policy verdict like any other, so it must be waivable, must
    // appear in `-J`, and must reach the store — all of which come free from
    // being an ordinary `Finding`, and all of which a private verdict path would
    // have had to re-implement. An over-budget set was previously visible only
    // to whoever thought to run `policy budget`, which is a report, not a gate.
    // The engine-side gates are skipped under a narrowing ON THE READ SURFACE: a
    // caller asking about one declared row is not asking about the budget or the
    // ledger, and running them would make a narrowed read fail for a reason it
    // did not ask about.
    //
    // THE SPAWNING SURFACE DOES NOT GET THAT SKIP, AND THE ASYMMETRY IS THE WHOLE
    // POINT (CLOUD-1186). The ledger gate lives engine-side precisely so a branch
    // cannot lower it by editing a rule table — and a narrowing that dropped it
    // here would be a one-token way to do exactly that, on the verb that runs
    // user-declared commands. A convenience on `check` is a hole on `enforce`.
    //
    // MEASURED, AND SHIPPED BROKEN FOR ONE DAY: CLOUD-1358 gave `enforce` a
    // `--rule` selector while this branch still read `only.is_empty()` alone, so
    // between that merge and this commit `batten enforce --rule <id>` skipped the
    // ledger. CLOUD-1186 had predicted that exact regression, in those words,
    // before the selector landed.
    //
    // The BUDGET keeps the skip on both surfaces: it is a measurement over
    // declared instruction files rather than a claim about this branch's
    // conduct, so a narrowed run failing on it is the "reason it did not ask
    // about" this comment already refuses. The ledger is the security property;
    // the budget is not.
    if only.is_empty() {
        findings.extend(engine_side_findings(&root, &config)?);
    } else if surface == Surface::Spawning {
        findings.extend(ledger_findings(&root, &config)?);
    }

    // The transcript capability (CLOUD-95), resolved BESIDE the runner rather than
    // through it: `runner` is a plain fn pointer over `(&[Rule], &Path)` with
    // nowhere to carry a transcript, and widening that signature to thread an
    // input no rule reads yet would be scaffolding for CLOUD-97/98 built before
    // either exists. This issue lands the substrate and reports its availability;
    // the rules that consume it widen the seam when they have findings to emit.
    //
    // A transcript this verb cannot read is REPORTED, never a veto (CLOUD-819).
    // It used to propagate as a `UsageError` — exit 1 — which stopped `check`
    // entirely, every unrelated tree rule with it, over one line written by a
    // host this repository does not control. That contradicted the invariant
    // twenty lines below: the only rule consuming this capability is declared
    // structurally unable to block (§0.3), so the surface feeding it must not
    // block either. Refusing also defended nothing — `Absent` already yields the
    // same silence at `Success`, so anyone wanting those rules quiet deletes the
    // file rather than tearing a byte of it.
    let capability = transcript::resolve(
        &root,
        config
            .transcript
            .as_ref()
            .and_then(|declared| declared.path.as_deref()),
    );
    report_transcript_capability(&capability, mode, err)?;

    // The first rule to consume the stream (CLOUD-267), which is what widens the
    // seam the comment above left open. It joins NEITHER `findings` nor
    // `any_blocking`: an advisory surface must be structurally unable to block
    // (§0.3), and routing it through `Finding` would put it behind
    // `--fail-on-warning`, which is a promotion path, not a tier.
    let self_writes = scan_self_writes(&capability, config.transcript.as_ref());
    report_self_writes(&self_writes, mode, err)?;

    // The judge (CLOUD-56), joining on exactly the terms above and for the same
    // §0.3 reason — beside `findings`, never into it. `check` never reaches
    // here: `run_static` already refused the run for carrying a spawning kind,
    // so this is not a second gate on the same question, it is the surface that
    // is allowed to answer it.
    if surface == Surface::Spawning {
        let raised = run_judges(err, mode, &config, &root)?;
        register_advisories(&raised, err)?;
        // The enforce surface's own findings, journalled from where they already
        // run (CLOUD-529). Gated on the surface and not on the kind: `check` must
        // reach no store write at all, which is what keeps its `read` effect
        // honest, and `run_state_record` stays the read surface's recorder.
        register_enforce_findings(&scan, mode, err)?;
    }

    // The baseline filter (CLOUD-67), immediately before the waiver filter.
    let findings = apply_baseline(findings, &scan, &root, mode, err)?;

    // The admission filter (CLOUD-1120), between the two — see its own doc. It
    // reads `base_ref`, bound once at the top: this used to rebind the identical
    // `overrides.config_from.as_deref()` under a second name, so one value had
    // two spellings in one function and a reader had to prove they agreed.
    let findings = apply_admissions(findings, &scan, &root, base_ref, mode, err)?;

    // The waiver filter (CLOUD-208), applied HERE and nowhere else. This function
    // is the single funnel `check` and `enforce` share — they differ only in the
    // `runner` above — so one insertion point covers both verbs, both channels and
    // the exit code. Inside `rules::run` it would also hide waived findings from
    // `-J`, and `run` has no access to resolved config beyond `&[Rule]`.
    //
    // Before rendering and before `any_blocking`: a waiver is a statement about
    // whether a finding is *counted*, not a fourth severity (`crate::severity`
    // says why a fourth rank would be a redesign). An expired waiver simply is not
    // found here, so the finding survives and the verdict below is the one the
    // rule always rendered — nobody had to act for the suppression to lapse.
    let (findings, waived) = waiver::apply(findings, &config.waivers, waiver::today()?);
    // The audit line every application owes, on the ERROR channel: ladder-gated
    // chatter that cannot reach a `-J` document even in principle. At `Normal`,
    // because a suppressed policy finding is not a detail a default run should
    // have to ask for.
    for applied in &waived {
        output::message(mode, Verbosity::Normal, err, &applied.line_text())?;
    }

    let delta = config_delta(config.base.as_ref());
    if json {
        // A data channel emits its document unconditionally — including the
        // empty one for a clean run. "Prints nothing when clean" (§6) is the
        // human channel's contract; JSON that is sometimes absent is unparseable.
        let report = CheckReport {
            fail_on_warning: config.fail_on_warning,
            transcript: transcript_view(&capability, &self_writes),
            config_delta: delta.as_ref().map(|weakenings| {
                weakenings
                    .iter()
                    .map(|weakening| DeltaView {
                        key: &weakening.key,
                        base: &weakening.base,
                        working: &weakening.working,
                    })
                    .collect()
            }),
            findings: findings
                .iter()
                .map(|finding| FindingView {
                    rule: &finding.rule,
                    path: &finding.path,
                    line: finding.line,
                    severity: finding.severity,
                    report: severity::promote(
                        severity::row_for_rule(finding.severity).report,
                        config.fail_on_warning,
                    ),
                    identity: &finding.identity,
                })
                .collect(),
            skipped: scan
                .unmet
                .iter()
                .map(|(rule, requires)| SkipView { rule, requires })
                .collect(),
            errored: scan
                .errored
                .iter()
                .map(|(rule, failure)| ErrorView {
                    rule,
                    class: failure.class.as_str(),
                })
                .collect(),
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // The delta precedes the findings and is summarised by a line naming the
        // ref and the count, so a reader sees "judged against origin/main, 2
        // keys weakened" before the findings that judgement produced. Emitted
        // only under `--config-from`, so a run without one keeps stdout exactly
        // the findings it has always been.
        if let (Some(weakenings), Some(reference)) = (delta.as_ref(), base_ref) {
            output::lines(out, weakenings.iter())?;
            writeln!(
                out,
                "config-from {reference}: {} weakened",
                weakenings.len()
            )?;
        }
        // Pointer only: location and the rule that fired, never the line text.
        // A rule-scoped finding (no line) prints its pointer without one rather
        // than inventing a line number it does not have. Both of those are
        // `Finding`'s own renderer now, not this site's.
        output::lines(out, &findings)?;
    }
    report_dispositions(mode, err, &scan)?;
    report_clean_run(json, mode, err, &findings, &config, &scan)?;
    // THE PIN IS MINTED HERE, and the position is the meaning (CLOUD-720):
    // "validated" is scoped to what this run already proved.
    if let Some(loaded) = config.base.as_ref() {
        trust::record_pin(&root, loaded);
    }
    // The severity axis reaches the exit contract exactly here: blocking is
    // derived through the taxonomy table, never name-matched (CLOUD-168), and
    // the outcome becomes a code in one place (§7).
    //
    // A FOLD OVER DISPOSITIONS since CLOUD-126, not a two-valued verdict.
    // `ExitCode::verdict` is deliberately still the two-valued constructor and
    // is not widened: `exit.rs` states that `Usage` and `Internal` are
    // unreachable through it, and that property is worth more than saving a
    // line here. So the fold sits one level up, where an erroring gate can
    // contribute `Internal` without any path making a *violation* reachable
    // from a failure.
    Ok(decision::fold(run_dispositions(
        &findings,
        &scan,
        config.fail_on_warning,
        &config.rules,
    )))
}

/// The per-gate dispositions this run reports, for [`decision::fold`]
/// (CLOUD-126).
///
/// One `Violation` for the whole finding set rather than one per finding, and
/// that is exact rather than a shortcut: `any_blocking` already folds severity
/// across findings through the taxonomy table, so re-deriving a per-finding
/// disposition here would be a second authority over the same question. What
/// this function adds is the axis severity cannot see — a rule that errored, and
/// a rule that never looked.
///
/// `Skipped` is emitted even though it contributes no code, because the fold's
/// input is the disposition multiset and dropping the members that fold to
/// nothing would make the function's output depend on which members happen to be
/// inert today.
fn run_dispositions(
    findings: &[rules::Finding],
    scan: &rules::Scan,
    fail_on_warning: bool,
    rules: &[rules::Rule],
) -> Vec<decision::Outcome> {
    let mut dispositions = Vec::with_capacity(scan.not_evaluated.len() + 1);
    dispositions.push(if rules::any_blocking(findings, fail_on_warning, rules) {
        decision::Outcome::Violation
    } else {
        decision::Outcome::Pass
    });
    for observation in scan.not_evaluated.values() {
        dispositions.push(match observation {
            findings::NotObserved::RuleErrored => decision::Outcome::Internal,
            findings::NotObserved::RuleSkipped => decision::Outcome::Skipped,
        });
    }
    dispositions
}

/// Say which gates did not decide, and why (CLOUD-125 §5, CLOUD-126 §5).
///
/// **On the message channel, and NOT gated on `machine`** — unlike
/// [`clean_run_notice`], which is. That asymmetry is the whole point rather than
/// an inconsistency: the clean-run notice is an onboarding courtesy a piped run
/// is right to suppress, whereas CLOUD-125 requires that "a run of only skipped
/// checks is byte-distinguishable from a run of only passing checks" — and on
/// the agent path, where both print nothing on stdout and exit `0`, this line is
/// the only thing that distinguishes them. Suppressing it under `machine` would
/// satisfy the clause for humans and leave it false for exactly the reader the
/// engine is built for. The waiver audit line beside it in [`run_rules`] is the
/// existing precedent for an ungated `Normal` message.
///
/// **Stdout is untouched**, which is what keeps this additive. A skipped rule is
/// not a finding, and putting it in the findings channel would break every
/// consumer that parses stdout as `path:line rule` — and change the bytes of
/// every clean run in a tree where some rules legitimately do not apply.
///
/// Only the rules with something to *say* are reported. A rule the engine
/// skipped for its own routing reasons — wrong scope, no glob, `allow`, an empty
/// match set — has no unmet requirement to name, and a line per such rule would
/// be forty lines of noise on this repository's own config saying only that the
/// engine works.
fn report_dispositions(mode: Mode, err: &mut dyn Write, scan: &rules::Scan) -> Result<()> {
    for (rule, missing) in &scan.unmet {
        output::message(
            mode,
            Verbosity::Normal,
            err,
            &format!("skipped {rule} — requires {missing}"),
        )?;
    }
    for (rule, failure) in &scan.errored {
        // The id, the class, and what the gate said — see `Scan::errored` for
        // why the reason travels rather than being withheld. A panic carries no
        // reason of the engine's, so its line is the id and the class alone.
        let line = if failure.reason.is_empty() {
            format!("errored {rule} — {}", failure.class.as_str())
        } else {
            format!(
                "errored {rule} — {} — {}",
                failure.class.as_str(),
                failure.reason
            )
        };
        output::message(mode, Verbosity::Normal, err, &line)?;
    }
    Ok(())
}

/// Announce a run served from the offline pin, on the messaging channel.
///
/// A degrade announces itself or it is not safe (CLOUD-720). Same channel and
/// rung as [`config::DEFAULTS_NOTE`], and for the same reason: stdout is the
/// findings channel and must be byte-identical to the run that reached the ref,
/// so a caller parsing it sees no new shape. No `-J` field pairs with this.
///
/// Split out of [`run_rules`] for [`report_clean_run`]'s reason — that funnel is
/// at clippy's line ceiling, and a notice is not what should push it over.
fn announce_degrade(mode: Mode, err: &mut dyn Write, base: Option<&trust::Loaded>) -> Result<()> {
    if let Some(trust::Provenance::Pin(evidence)) = base.map(|base| &base.provenance) {
        output::message(mode, Verbosity::Normal, err, &trust::pinned_note(evidence))?;
    }
    Ok(())
}

/// The working-tree-vs-base delta, or `None` when no base ref was named.
///
/// *Reporting*, not a verdict: the exit code comes from the rules as evaluated
/// against the base config, which is what makes the gate un-loweable. Turning a
/// weakening into a violation on its own is `config lint`'s job (CLOUD-87),
/// which reuses this same comparison.
///
/// The base is the one `resolve` took its policy from, never a second load of
/// the same ref (CLOUD-720): two loads could reach two answers — a resolve
/// served from a pin followed by a delta that refuses — which would be one run
/// disagreeing with itself about one ref.
///
/// A working authority that cannot be read is not a reason to abandon the
/// verdict. The rules being evaluated are the trusted ones and the exit code is
/// computable; this feeds the *report*. Letting it abort turned the maximal
/// weakening — delete `batten.toml` — into exit 1, a code every mediating
/// harness reads as "do not block", in the one mechanism whose stated purpose is
/// to be un-loweable (CLOUD-243). An unreadable authority grants no policy, so
/// it is compared as one that declares nothing: every key the base declares
/// reports as removed, each under its own key path.
fn config_delta(base: Option<&trust::Loaded>) -> Option<Vec<trust::Weakening>> {
    let base = base?;
    let working = config::load(&Path::new(".").join(config::CONFIG_FILE))
        .unwrap_or_else(|_| config::Config::declaring_nothing());
    Some(trust::weakenings(&base.config, &working))
}

/// Say what a clean run did, if anything (CLOUD-222).
///
/// The write half, split from [`clean_run_notice`]'s decision half so the branch
/// that a TTY-less test cannot reach is still decided by something a table can
/// drive. Kept out of [`run_rules`] because that funnel is already at clippy's
/// line ceiling, and a notice is not what should push it over.
fn report_clean_run(
    json: bool,
    mode: Mode,
    err: &mut dyn Write,
    findings: &[rules::Finding],
    config: &resolve::Resolved,
    scan: &rules::Scan,
) -> Result<()> {
    if let Some(note) = clean_run_notice(
        json,
        mode.machine,
        findings.is_empty(),
        config.rules.len(),
        scan.not_evaluated.len(),
    ) {
        output::message(mode, Verbosity::Normal, err, &note)?;
    }
    Ok(())
}

/// What a clean run says on stderr, or `None` when it says nothing (CLOUD-222).
///
/// A clean `check` prints nothing on stdout and exits `0` — §6's cheapest
/// possible signal, and right for the agent path, where the exit code is the
/// whole interface and every byte printed is context spent. It is wrong exactly
/// once: a newcomer who has just paid a cold build cannot tell "evaluated N
/// rules, all clean" from "nothing ran", so the first useful thing the tool does
/// is invisible to the only reader with no priors to fill the silence.
///
/// Four things this returns `None` for, and each is load-bearing:
///
/// * **`machine`** — §4's already-resolved attendedness (`!stderr_tty || <CI
///   signal>`), read here rather than re-derived. A piped or CI run cannot reach
///   the notice, so the agent path keeps byte-for-byte the output it has today
///   **by construction**, which is what makes that assertion testable rather than
///   a promise a reviewer has to take on trust.
/// * **`json`** — the data channel emits its document and nothing else; a `-J`
///   caller parses stdout and this would be noise beside it.
/// * **not clean** — a run with findings has already said something worth more.
/// * **nothing declared and nothing run** — see below.
///
/// The count is the rules that actually **evaluated**, `not_evaluated`
/// subtracted: "checked 12 rules" over a run where four never looked is the
/// false green this engine exists to refuse. A config declaring no rules at all
/// still gets the line, and that is the point rather than an oversight — `0` is
/// the honest answer to "what ran", and it is exactly the reader who suspects
/// nothing ran who most needs to be told they are right.
fn clean_run_notice(
    json: bool,
    machine: bool,
    clean: bool,
    declared: usize,
    not_evaluated: usize,
) -> Option<String> {
    if json || machine || !clean {
        return None;
    }
    let evaluated = declared.saturating_sub(not_evaluated);
    Some(format!("checked {evaluated} rule(s) — nothing to report"))
}

/// A key's value as one pointer-line token.
///
/// A list is reported as its length rather than its contents: the default
/// channel points at policy, it does not carry it (non-negotiable rule 4). An
/// object is reported the same way for the same reason.
fn pointer_value(entry: &resolve::Attributed) -> String {
    match &entry.value {
        serde_json::Value::Array(items) => items.len().to_string(),
        serde_json::Value::Object(fields) => fields.len().to_string(),
        serde_json::Value::String(text) => text.clone(),
        serde_json::Value::Null => "-".to_owned(),
        other => other.to_string(),
    }
}

/// `batten lint brief [<path>]` (CLOUD-84).
///
/// Reads a delegation brief from `path`, or from stdin when it is `None` or `-` —
/// the same `-` convention `config lint --host-rules` uses, so a brief can be
/// piped straight from whatever composed it.
///
/// # Exit contract
///
/// The one table, no per-verb exception (non-negotiable rule 5): a missing
/// section is a **policy verdict**, [`ExitCode::Violation`] (`2`), and input that
/// cannot be read is [`ExitCode::Usage`] (`1`). CLOUD-84's Ready block originally
/// stated these the other way round — the `mise-tasks/*-check` shell convention,
/// which is the exact inverse — and CLOUD-307 named this clause by id. Shipping
/// `1` for a missing section would make a policy verdict read to every mediating
/// harness as a config error: fail-loud-do-not-block, on the surface whose whole
/// purpose is to block.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) when the named path cannot be read, and
/// when the input is not UTF-8. A brief is prose; bytes that are not text are a
/// caller mistake, and answering "no missing sections" over them would be a pass
/// nobody measured.
fn run_lint_brief(path: Option<&str>, json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let text = match path {
        None | Some("-") => {
            let mut buffer = Vec::new();
            std::io::stdin().read_to_end(&mut buffer)?;
            String::from_utf8(buffer).map_err(|_| {
                UsageError::raise("the brief on stdin is not valid UTF-8".to_owned())
            })?
        }
        Some(source) => std::fs::read_to_string(source).map_err(|err| {
            UsageError::raise(format!("cannot read the brief at {source}: {err}"))
        })?,
    };

    let report = brief::problems(&text);
    if json {
        // Emitted unconditionally, including the clean run: JSON that is
        // sometimes absent is unparseable, the same reasoning `config lint -J`
        // records. Ids and counts only — never a byte of the brief (rule 4).
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // A complete brief is SILENT (CLOUD-84 §7(a)). This is the one verb where
        // the house habit of stating a count even at zero is overridden by the
        // issue, and deliberately so: `lint brief` is meant to sit inline in a
        // dispatch path, where a line per successful handoff is noise the reader
        // learns to skip.
        for line in report.lines() {
            writeln!(out, "{line}")?;
        }
    }
    Ok(ExitCode::verdict(!report.is_clean()))
}

/// `batten config deprecations --against <ref>` (CLOUD-360 §2).
///
/// Its own function rather than an arm, for the seam `config_of` already uses:
/// `run_config` reached `clippy::too_many_lines` when this landed, and a verb
/// with three distinct exit outcomes is the natural place to split.
///
/// THREE OUTCOMES, and the third is the one worth reading. `0` when nothing left
/// the surface unannounced, `2` when something did — the policy verdict, same as
/// any other finding — and `3` when the baseline could not be read at all.
///
/// # Errors
///
/// Raises (→ exit `3`) when the ref carries no published schema, and a
/// [`UsageError`] (→ exit `1`) when either schema is unreadable. Never `0` for
/// either: reporting "no key was removed" having compared nothing is the vacuous
/// pass CLOUD-251 names, and it is the failure this gate would have if an
/// unreadable baseline were treated as an empty schema.
fn run_config_deprecations(json: bool, against: &str, out: &mut dyn Write) -> Result<ExitCode> {
    let Ok(published) = git::show(Path::new("."), against, config::SCHEMA_PATH) else {
        // THE DOCUMENT IS EMITTED ANYWAY. A data channel that is sometimes absent
        // is unparseable by the caller that asked for it, so the could-not-look
        // answer is a document too — distinguished by `baseline`, never by an
        // empty list that reads as clean.
        if json {
            let report = DeprecationReport {
                against,
                baseline: "unavailable",
                removed_without_window: &[],
            };
            writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
        }
        anyhow::bail!("no published schema at {against}, so no removal could be judged");
    };
    let released = config::schema_keys(&published, against)?;
    let derived = config::schema()?;
    let current = config::schema_keys(&derived, "the derived schema")?;
    let unannounced = config::removals_unannounced(
        &released,
        &current,
        config::DEPRECATED_KEYS,
        config::RETIRED_KEYS,
    );
    if json {
        let report = DeprecationReport {
            against,
            baseline: "read",
            removed_without_window: &unannounced,
        };
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        // Pointer-only: the key and the remedy, never the schema body.
        for key in &unannounced {
            writeln!(
                out,
                "{key} removed since {against} with no deprecation window"
            )?;
        }
        // The count is stated even at zero, so silence cannot be mistaken for
        // "the gate did not run".
        writeln!(
            out,
            "config-deprecations: {} unannounced removal(s) against {against}",
            unannounced.len()
        )?;
    }
    Ok(ExitCode::verdict(!unannounced.is_empty()))
}

fn run_config(
    command: &ConfigCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        ConfigCommand::Show { json } => {
            let config = resolve::resolve(Path::new("."), overrides)?;
            // The document is the resolver's own serialization paired with the
            // layer that set each key — never composed by hand here, so the
            // emitted shape is stated once, in `resolve::Resolved` (§8).
            let document = config.attributed()?;
            if *json {
                // stdout is the answer: one byte-stable document, keys sorted.
                writeln!(out, "{}", serde_json::to_string_pretty(&document)?)?;
            } else {
                // The default channel stays pointer/count (non-negotiable rule
                // 4): one `<key> <value> <source> <provenance>` line per key,
                // with the rule set as a COUNT — printing rule bodies here would
                // put policy content on the channel that is meant to point at it.
                //
                // The class is a fourth FIELD rather than a decoration on the
                // third, so `<source>` stays exactly the token it was and a
                // reader splitting the line keeps the column it already read
                // (CLOUD-332, CLOUD-722).
                for (key, entry) in &document {
                    writeln!(
                        out,
                        "{key} {} {} {}",
                        pointer_value(entry),
                        entry.source.as_str(),
                        entry.provenance.as_str()
                    )?;
                }
            }
            Ok(ExitCode::Success)
        }
        // The alarm beside `--config-from`'s control (CLOUD-87): a smell is a
        // verdict about the *config*, so any smell is a Violation — the same
        // code a rule finding returns, because it is the same kind of answer.
        // An unparseable config is a Usage error, raised by the loader.
        // The epoch is a pure function of the tracked files' bytes, so it is
        // read-effect and byte-stable. An unreadable tracked path propagates as
        // a Usage error (exit 1) rather than being skipped: the `[epoch]
        // tracked` set is config, so a path it names that cannot be read is
        // unreadable config, which §7 routes to 1 — see `epoch`.
        ConfigCommand::Epoch { json, no_cache } => {
            // The epoch covers whichever authority governed the run: under
            // `--config-from` that is the ref's surface, never the working
            // tree's (CLOUD-31). An epoch attributing a run to a config that
            // did not govern it would be worse than none.
            //
            // The cached path is byte-identical to the cold one or it is a bug
            // (CLOUD-232); `--no-cache` selects the cold one so a test can hold
            // the two side by side.
            let (value, tracked) = if *no_cache {
                epoch::describe(Path::new("."), overrides.config_from.as_deref())?
            } else {
                epoch::describe_cached(Path::new("."), overrides.config_from.as_deref())?
            };
            if *json {
                // The digest alone cannot say what it covers, and a caller
                // stamping it onto a record needs both halves — so `-J` adds the
                // governing surface rather than re-encoding the value. Paths, not
                // bytes: still a pointer (non-negotiable rule 4).
                let report = EpochReport {
                    epoch: &value,
                    tracked: &tracked,
                };
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
            } else {
                writeln!(out, "{value}")?;
            }
            Ok(ExitCode::Success)
        }
        ConfigCommand::Deprecations { json, against } => {
            run_config_deprecations(*json, against, out)
        }
        ConfigCommand::Lint { json, host_rules } => {
            // The date the expiry smell is computed against, read once at this
            // boundary and threaded in as data (`waiver`'s module docs say why).
            let mut smells = lint::run(
                Path::new("."),
                overrides.config_from.as_deref(),
                waiver::today()?,
            )?;
            // The drift half (CLOUD-54), added only when the caller supplied a
            // payload — so lint's behaviour without the flag is byte-identical
            // to what it was.
            if let Some(source) = host_rules {
                smells.extend(lint::host_drift(Path::new("."), source, overrides)?);
                smells.sort();
            }
            if *json {
                // Emitted unconditionally, including the clean run: JSON that is
                // sometimes absent is unparseable. `at` is rendered through
                // `Where`'s own `Display` rather than by deriving `Serialize` on
                // the domain type, so the line-or-key union has exactly one
                // spelling across both channels.
                let report = LintReport {
                    smells: smells
                        .iter()
                        .map(|smell| SmellView {
                            at: smell.at.to_string(),
                            id: smell.id,
                        })
                        .collect(),
                };
                writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
            } else {
                output::lines(out, &smells)?;
                // The count is stated even at zero: silence would be
                // indistinguishable from "the lint did not run".
                writeln!(out, "config-lint: {} smell(s)", smells.len())?;
            }
            // THE ADMISSION ARM, and it runs only under a base ref — which is the
            // same condition that produces a base-ref smell in the first place, so
            // an unarmed run's behaviour and exit code are byte-identical to what
            // they were. That symmetry is load-bearing rather than tidy: an
            // unarmed `config lint` reports no weakening to admit, and a run that
            // admitted something it had not computed would be deciding blind.
            let Some(base) = overrides.config_from.as_deref() else {
                return Ok(ExitCode::verdict(!smells.is_empty()));
            };
            let adjudicated = lint::admissions(
                &smells,
                &lint::declared(Path::new("."), base)?,
                &lint::groom(
                    // `git_dir`, not `common_dir`: a claim is a per-worktree
                    // fact, and `claim::mint` writes it under the same one.
                    &git::git_dir(Path::new("."))?.join("batten-receipts"),
                    git::current_branch(Path::new("."))?.as_deref(),
                ),
            );
            let refused = adjudicated
                .iter()
                .filter(|(_, admission)| *admission == lint::Admission::Refused)
                .count();
            if !*json {
                for (smell, admission) in &adjudicated {
                    if *admission != lint::Admission::Refused {
                        // Pointer plus a verdict token, never the clause's prose:
                        // a reader gets which pair was admitted and on what
                        // evidence, and the reasoning stays in the groomed body
                        // where a reviewer reads it in context.
                        writeln!(
                            out,
                            "config-lint: admitted {} {} ({})",
                            smell.id,
                            smell.at,
                            admission.as_str()
                        )?;
                    }
                }
            }
            Ok(ExitCode::verdict(refused != 0))
        }
    }
}

/// Diagnose whether Batten can run here (CLOUD-66).
///
/// The exit code comes from [`doctor::Report::code`], whose range excludes
/// [`ExitCode::Violation`] by construction: a diagnostic never renders a policy
/// verdict, so a mediating harness can never read "this checkout is
/// misconfigured" as a deny (§7).
fn run_doctor(command: &cli::DoctorCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match *command {
        cli::DoctorCommand::Diagnose { json } => run_diagnose(json, out),
        cli::DoctorCommand::Hooks { json } => run_doctor_hooks(json, out),
        cli::DoctorCommand::Mediator { json } => run_doctor_mediator(json, out),
        cli::DoctorCommand::Session { json } => run_doctor_session(json, out),
        cli::DoctorCommand::Egress { json } => run_doctor_egress(json, out),
    }
}

/// Was the engine the registrations reach built from this tree (CLOUD-1349)?
///
/// `doctor hooks` answers whether the registrations reach an engine; this answers
/// WHICH one, and the gap between those two questions is where a session spends
/// six hours believing it is mediated. Rationale, and why it is a sub-verb rather
/// than a fourth check in the bare report, on [`doctor::Mediator`].
///
/// One pointer line, never a digest: a hash is stable per content but varies per
/// machine, so emitting one would defeat the byte-stability §6 requires of this
/// verb's output while telling the reader nothing they can act on. The remedy is
/// `mise run install:local` and the verdict is what says whether to run it.
/// Would the agent proxy carry this container's requests (CLOUD-1399)?
///
/// Reads THIS process's environment, which is the whole point: a consumer's own
/// check asking the same question through its task runner reads a value that
/// runner's env block has already corrected — so it grades the repair and reports
/// the container as fenced while the container's own value is unfenced. `batten` is
/// invoked directly by the setup one-liner and by every hook registration, so what
/// it reads here is what the container actually shipped.
///
/// One pointer line, never the values: a `NO_PROXY` list is long, machine-specific
/// and would defeat the byte-stability §6 requires of this verb, while telling the
/// reader nothing they can act on. The remedy is a change to the container's
/// Environment variables field, and the verdict is what says whether to make it.
fn run_doctor_egress(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose_egress();
    if json {
        // A data channel emits its document unconditionally, including when the
        // container is unproxied: JSON that is sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        output::line(out, &report)?;
    }
    Ok(report.code())
}

fn run_doctor_mediator(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose_mediator(Path::new("."));
    if json {
        // A data channel emits its document unconditionally, including when the
        // mediator is current: JSON that is sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        output::line(out, &report)?;
    }
    Ok(report.code())
}

fn run_diagnose(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose(Path::new("."));
    if json {
        // A data channel emits its document unconditionally, including for a
        // healthy repository: JSON that is sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        output::lines(out, &report.checks)?;
        let failed = report.checks.iter().filter(|check| !check.ok).count();
        writeln!(
            out,
            "doctor: {} check(s), {failed} failed",
            report.checks.len()
        )?;
    }
    Ok(report.code())
}

/// Is batten wired on every hook surface of every harness (CLOUD-777)?
///
/// The question `doctor` exists to answer, asked of the one thing it could not:
/// its own installation. It ships to a consumer, which the ~300 lines of bash it
/// replaces never did — a repository adopting Batten had no way to ask *am I
/// wired?* at all.
///
/// The exit code comes from [`doctor::WiringReport::code`], whose range excludes
/// [`ExitCode::Violation`] by construction. A sub-verb inherits the promise the
/// parent makes: a mediating harness reads `2` as a deny, and "your wiring is
/// wrong" is not "policy says no".
///
/// The pointer line is `<harness> <event> <reason>` — a host token and a stable
/// reason id, never a path (§6, rule 4). A harness with nothing wrong renders one
/// `ok` line rather than nothing, so a silent run and a healthy one are
/// distinguishable.
fn run_doctor_hooks(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose_hooks(Path::new("."));
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
    } else {
        for harness in &report.harnesses {
            if harness.findings.is_empty() {
                writeln!(
                    out,
                    "{} ok {} registration(s), {} sibling(s)",
                    harness.harness, harness.registrations, harness.siblings
                )?;
                continue;
            }
            for finding in &harness.findings {
                writeln!(
                    out,
                    "{} {} {}",
                    harness.harness, finding.event, finding.reason
                )?;
            }
        }
        let failed = report
            .harnesses
            .iter()
            .filter(|harness| !harness.ok)
            .count();
        writeln!(
            out,
            "doctor hooks: {} harness(es), {failed} unwired",
            report.harnesses.len()
        )?;
    }
    Ok(report.code())
}

/// `doctor session` — the exit code that answers "is this session safe to end".
///
/// Three codes for three answers, which is the whole point of the verb
/// (CLOUD-1376): `0` nothing open, `1` work declared and unfinished, `3`
/// could-not-look. A caller may quote the code; it cannot quote an opinion.
///
/// [`ExitCode::Violation`] is unreachable, for [`doctor::WiringReport::code`]'s
/// reason: a sub-verb of `doctor` is a diagnosis, a mediating harness reads `2`
/// as a deny, and "you have unfinished work" is not "policy says no".
///
/// **Could-not-look is `3` and never `0`.** That single mapping is the row's
/// deliverable: the defect being fixed is an absent reading reported as a clean
/// one, so the arm with nothing to read must not share a code with the arm that
/// read and found nothing.
fn run_doctor_session(json: bool, out: &mut dyn Write) -> Result<ExitCode> {
    let report = doctor::diagnose_session(Path::new("."));
    if json {
        writeln!(out, "{}", serde_json::to_string_pretty(&report)?)?;
        return Ok(session_code(&report));
    }
    match (report.open, report.total) {
        (Some(open), Some(total)) if open > 0 => {
            writeln!(
                out,
                "doctor session: {open} of {total} declared task(s) open — {}",
                report.ids.join(" ")
            )?;
        }
        (Some(_), Some(total)) => {
            writeln!(out, "doctor session: 0 of {total} declared task(s) open")?;
        }
        // Silent on stdout for the unreadable arm: §6 keeps a could-not-look off
        // the data channel, and the exit code carries it.
        _ => {
            writeln!(
                out,
                "doctor session: no readable task store — this is could-not-look, never a clean"
            )?;
        }
    }
    Ok(session_code(&report))
}

fn session_code(report: &doctor::SessionReport) -> ExitCode {
    match report.open {
        None => ExitCode::Internal,
        Some(0) => ExitCode::Success,
        Some(_) => ExitCode::Usage,
    }
}

/// `show agent` (CLOUD-1180): what an agent may do in this repository.
///
/// # Absent config is a STATE; a config that will not LOAD is not
///
/// CLOUD-1180's §7(d) asks for a deterministic unavailable state rather than an
/// error where a repository declares no policy, and it gets one for free:
/// `resolve` SUCCEEDS with the built-in defaults where no authority exists, so
/// absent already answers `configured: false` with the defaults' own gates
/// listed. `Authority::Present` is what `configured` reads, never whether a
/// `Resolved` was obtained.
///
/// **This used to swallow the resolve's error with `ok()`, and that was a false
/// safety claim rather than a tidy fallback.** Since absent never errors, the
/// only thing `ok()` could ever discard was a config that EXISTS and will not
/// load — and `capabilities(None)` reports `gates: []`, so a malformed
/// `batten.toml` answered "nothing is enforced here" at exit `0`. That is the
/// one direction [`crate::agent`]'s module doc says this verb must never be
/// wrong in, and the sentence that stood here asserted the opposite of what the
/// code did: it claimed a malformed config was "NOT swallowed with it" while
/// the `ok()` two lines down swallowed exactly that, on the reasoning that both
/// cases "mean no gates are in force" — which is false of both. Absent leaves
/// the defaults in force; unreadable leaves the question unanswered.
///
/// So the error propagates. An agent reading this verb gets an answer or an
/// error, never a document that understates what governs it. `config lint` is
/// still where a broken file is DIAGNOSED; this verb's job is to refuse to
/// speak for one.
///
/// # `read`, structurally
///
/// Every input is already in hand or derived from the compiled surface;
/// [`agent::capabilities`] takes the config by reference and touches no
/// filesystem, so there is no path from this verb to a write or a spawn.
fn run_show_agent(json: bool, overrides: &Overrides, out: &mut dyn Write) -> Result<ExitCode> {
    let config = resolve::resolve(Path::new("."), overrides)?;
    let reading = agent::capabilities(Some(&config));
    if json {
        // Unconditional, including when nothing is configured: JSON that is
        // sometimes absent is unparseable.
        writeln!(out, "{}", serde_json::to_string_pretty(&reading)?)?;
    } else {
        output::lines(out, &reading.read_only)?;
        output::lines(out, &reading.exit_codes)?;
        output::lines(out, &reading.gates)?;
        output::line(out, &reading)?;
    }
    // Always `0`: this verb reports a state and judges nothing, so there is no
    // finding for it to raise and no `2` it could honestly mint.
    Ok(ExitCode::Success)
}

fn run_spec(format: SpecFormat, out: &mut dyn Write) -> Result<ExitCode> {
    let described = spec::document(&surface::command());
    match format {
        SpecFormat::Json => {
            let json = spec::to_json(&described)?;
            writeln!(out, "{json}")?;
        }
    }
    Ok(ExitCode::Success)
}

/// Emit an artifact derived from the command surface, on stdout.
///
/// Stdout-only is what makes `generate`'s `read` effect structurally honest
/// (§5): the binary writes no file, so refreshing a committed artifact is the
/// caller's redirect (`mise run completions`) and never a side effect of the
/// verb. The completions are generated from the same [`surface::command`] tree
/// the parser is built from, so a committed script cannot describe a surface the
/// binary does not have — which is the property `derived-check` gates.
///
/// Man pages and markdown join on the same terms (CLOUD-69): every format here
/// walks the one [`surface::SURFACE`]-built tree, and every one of them returns
/// bytes for the caller to redirect.
fn run_generate(command: &GenerateCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match command {
        GenerateCommand::Completions { shell } => {
            clap_complete::generate(*shell, &mut surface::command(), "batten", out);
        }
        // One page per command, selected by the same root-relative path the
        // spec and the §5 effect table are keyed by. A single page for the
        // whole tree would document the root and none of the verbs, which is
        // the shape `man batten-config-show` cannot resolve.
        GenerateCommand::Man { command } => {
            write!(
                out,
                "{}",
                render::man(&surface::command(), command.as_deref())?
            )?;
        }
        // The whole surface in one document — the CLI reference CLOUD-171
        // renders at publish time. Deliberately not a committed artifact: a
        // reference derived from the binary at publish time is current by
        // construction, and a committed copy would be the second authority
        // this whole module exists to remove.
        GenerateCommand::Markdown => {
            write!(
                out,
                "{}",
                render::markdown(&spec::describe(&surface::command()))
            )?;
        }
        // Two surfaces, two derivations (CLOUD-239): one schema describing both
        // is what let a validator vouch for override keys the loader drops.
        GenerateCommand::Schema { surface } => match surface {
            cli::SchemaSurface::Authority => writeln!(out, "{}", config::schema()?)?,
            cli::SchemaSurface::Override => writeln!(out, "{}", config::override_schema()?)?,
            cli::SchemaSurface::PolicyInput => {
                writeln!(out, "{}", policy::tree_input_schema()?)?;
            }
            cli::SchemaSurface::PolicyCall => {
                writeln!(out, "{}", policy::call_input_schema()?)?;
            }
        },
        // A refusal rather than empty output for a harness that is a contract
        // and not a host: emitting `{}` would answer "this host registers
        // nothing", which is a different claim from "there is nothing to
        // register with". `UsageError` is exit 1 — the caller named something
        // that cannot be asked for, which is a statement about the invocation.
        GenerateCommand::Hooks { harness } => {
            let wiring = harness.wiring().ok_or_else(|| {
                UsageError::raise(format!(
                    "generate hooks: {} is the neutral contract, not a host — it has no \
                     hook-config surface to register in",
                    harness.as_str()
                ))
            })?;
            writeln!(out, "{}", hook::render_wiring(*harness, &wiring))?;
        }
    }
    Ok(ExitCode::Success)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// The whole decision as a table, because the branch that matters cannot be
    /// reached over a spawned process: this sandbox gives a test no TTY, so
    /// `machine` is always true there and the attended arm would never run. The
    /// e2e suite asserts the SILENT half against the real binary; this asserts
    /// that the other half exists and is reached for the right reasons
    /// (`.claude/rules/rust.md`: extract the decision rather than assert a
    /// conclusion over a precondition the environment never created).
    #[test]
    fn a_clean_run_speaks_only_when_a_person_is_reading() {
        // (json, machine, clean) -> whether a line is emitted.
        let cases = [
            ((false, false, true), true, "attended, clean, human channel"),
            (
                (false, true, true),
                false,
                "piped or CI: the agent path is silent",
            ),
            (
                (true, false, true),
                false,
                "-J: the document is the whole answer",
            ),
            (
                (false, false, false),
                false,
                "findings said something already",
            ),
            ((true, true, false), false, "none of the three hold"),
        ];
        for ((json, machine, clean), speaks, why) in cases {
            assert_eq!(
                clean_run_notice(json, machine, clean, 3, 0).is_some(),
                speaks,
                "{why}"
            );
        }
    }

    /// The count is what RAN, not what was declared. A rule that never looked
    /// must not be counted as one that passed — that is the false green the
    /// engine exists to refuse, and it would be invisible in a line that reads
    /// reassuringly either way.
    #[test]
    fn the_count_subtracts_the_rules_that_never_looked() {
        assert_eq!(
            clean_run_notice(false, false, true, 12, 4).unwrap(),
            "checked 8 rule(s) — nothing to report"
        );
        // Saturating, not panicking: the two numbers come from different places
        // and an inverted pair must not take the process down over a message.
        assert_eq!(
            clean_run_notice(false, false, true, 1, 9).unwrap(),
            "checked 0 rule(s) — nothing to report"
        );
    }

    /// A `base` git cannot resolve is COULD-NOT-LOOK, never "no key here".
    ///
    /// CLOUD-787. `key_facts` is only ever called once a `requires_key` row has
    /// already selected the command, so every failure inside it is the question
    /// being unanswerable — no checkout, a shallow clone whose history is not
    /// there to read, a `base` that resolves to nothing. "Looked and found no
    /// key" is a different answer and it belongs to the CALLER, which is the one
    /// that knows whether any row asked.
    ///
    /// Collapsing the two is the defect the three-valued contract exists to
    /// prevent: `IsNot` here would claim the boundary had inspected a branch's
    /// history and found no issue key, on a call where it never read one.
    ///
    /// Fails by: returning `Look::IsNot` from `key_facts`'s failure arm.
    #[test]
    fn an_unresolvable_base_could_not_look_rather_than_finding_no_key() {
        let facts = key_facts("refs/heads/definitely-not-a-ref-cloud-787");
        assert!(
            facts.could_not_look(),
            "an unresolvable base is could-not-look, got {}",
            facts.as_str()
        );
        assert_eq!(facts.as_str(), "could-not-look");
        assert!(
            !matches!(facts, facts::Look::IsNot),
            "could-not-look must not be spelled as looked-and-found-nothing"
        );
    }

    /// A config declaring nothing still gets the line. The reader who suspects
    /// nothing ran is exactly the one who needs to be told they are right, and
    /// `0` is the honest answer rather than a reason to stay silent.
    #[test]
    fn declaring_no_rules_is_reported_rather_than_hidden() {
        assert_eq!(
            clean_run_notice(false, false, true, 0, 0).unwrap(),
            "checked 0 rule(s) — nothing to report"
        );
    }
}
