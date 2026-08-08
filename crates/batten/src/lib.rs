//! Batten is a repo-agnostic policy engine.
//!
//! It gates what gets written, proves what was verified, and refuses to let
//! unlanded work appear finished — enforcing one repository's policy consistently
//! at the pre-commit layer, in CI, and at an agent's tool call.
//!
//! This crate exposes the library surface ([`run`]) that the `batten` binary is a
//! thin wrapper around. Keeping the logic in the library keeps it testable and
//! keeps the binary's `main` trivial.

pub mod cli;
pub mod config;
pub mod effect;
pub mod error;
pub mod exit;
pub mod git;
pub mod hook;
pub mod identity;
pub mod lint;
pub mod receipt;
pub mod resolve;
pub mod rules;
pub mod severity;
pub mod spec;
pub mod state;
pub mod surface;
pub mod trust;

use std::io::{Read, Write};
use std::path::Path;

use anyhow::Result;

pub use cli::{Cli, Command, ConfigCommand, GenerateCommand, ReceiptCommand, SpecFormat};
pub use config::Config;
pub use effect::Effect;
pub use error::{Denial, UsageError};
pub use exit::ExitCode;
pub use resolve::{Overrides, Resolved, Source};
pub use severity::{AdvisoryTier, Mapping, ReportLevel, RuleSeverity};

/// Execute a parsed [`Cli`], writing any data output to `out`, and return the
/// [`ExitCode`] to hand back to the OS.
///
/// Data output goes to `out` (the binary passes stdout) rather than through a
/// `print!`, so the library stays byte-stable and testable and the
/// stdout-is-the-answer split of the output contract is honoured.
///
/// # Errors
///
/// Returns an error when a command cannot complete because of an underlying
/// failure (I/O, a missing external tool, or an internal invariant violation).
/// Such errors map to [`ExitCode::Internal`] at the boundary; a *policy
/// violation*, by contrast, is a normal return of [`ExitCode::Violation`].
pub fn run(cli: Cli, out: &mut dyn Write) -> Result<ExitCode> {
    let Cli {
        strictness,
        fail_on_warning,
        config_from,
        command,
    } = cli;
    // The flag layer of the §8 precedence chain; every config read in this run
    // resolves through it, so a flag can never apply to one verb and not another.
    let overrides = Overrides {
        strictness,
        fail_on_warning,
        config_from,
    };
    match command {
        // Unreachable in practice: `arg_required_else_help` has clap offer the
        // subcommand listing (a usage error, exit 1) before parse returns. Kept
        // total — the workspace lints forbid panicking on a reachable path.
        None => Ok(ExitCode::Success),
        Some(Command::Check { json }) => run_rules(out, &overrides, rules::run_static, json),
        Some(Command::Enforce { json }) => run_rules(out, &overrides, rules::run_all, json),
        Some(Command::Config { command }) => run_config(&command, &overrides, out),
        Some(Command::Spec { format }) => run_spec(format, out),
        Some(Command::Generate { command }) => run_generate(&command, out),
        Some(Command::Hook { harness }) => run_hook(harness, out),
        // The receipt verbs read their own git facts; the §8 config chain does
        // not apply — a receipt records policy (as a digest), it never resolves it.
        Some(Command::Receipt { command }) => match command {
            ReceiptCommand::Record { check } => receipt::run_record(&check),
            ReceiptCommand::Status { check } => receipt::run_status(&check, out),
        },
    }
}

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
fn run_hook(harness: hook::Harness, out: &mut dyn Write) -> Result<ExitCode> {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return Ok(ExitCode::Success);
    }
    let bypass = std::env::var_os("BATTEN_GH_GUARD_BYPASS").is_some_and(|v| !v.is_empty());
    let Some(envelope) = hook::decode(harness, &raw) else {
        return Ok(ExitCode::Success);
    };
    match hook::adjudicate(&envelope, bypass) {
        hook::Decision::Allow => Ok(ExitCode::Success),
        hook::Decision::Deny(reason) => match harness {
            hook::Harness::ClaudeCode => {
                writeln!(
                    out,
                    "{}",
                    hook::encode_claude_deny(&envelope.event, &reason)?
                )?;
                Ok(ExitCode::Success)
            }
            hook::Harness::ExitCode => Err(Denial::raise(reason)),
        },
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
#[derive(Debug, serde::Serialize)]
struct FindingView<'a> {
    rule: &'a str,
    path: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    line: Option<usize>,
    severity: RuleSeverity,
    report: severity::ReportLevel,
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
    findings: Vec<FindingView<'a>>,
}

/// One weakened key in the `-J` payload, the same pointer the human channel
/// prints, split into its parts so a consumer need not parse the arrow.
#[derive(Debug, serde::Serialize)]
struct DeltaView<'a> {
    key: &'a str,
    base: &'a str,
    working: &'a str,
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
fn run_rules(
    out: &mut dyn Write,
    overrides: &Overrides,
    runner: fn(&[rules::Rule], &Path) -> Result<Vec<rules::Finding>>,
    json: bool,
) -> Result<ExitCode> {
    // The *resolved* rule set, so a local override's added rules are gates a run
    // actually applies rather than config the tool merely prints. The promotion
    // setting comes off the same resolution, so one §8 chain decides both.
    let base_ref = overrides.config_from.as_deref();
    let config = resolve::resolve(Path::new("."), overrides)?;
    let findings = runner(&config.rules, Path::new("."))?;

    // The working-tree-vs-base delta, computed only when a base ref was named.
    // It is *reporting*, not a verdict: the exit code below comes from the rules
    // as evaluated against the base config, which is what makes the gate
    // un-loweable. Turning a weakening into a violation on its own is `config
    // lint`'s job (CLOUD-87), which reuses this same comparison.
    let delta = match base_ref {
        Some(reference) => {
            let base = trust::load_base(Path::new("."), reference)?;
            let working = config::load(&Path::new(".").join(config::CONFIG_FILE))?;
            Some(trust::weakenings(&base, &working))
        }
        None => None,
    };
    if json {
        // A data channel emits its document unconditionally — including the
        // empty one for a clean run. "Prints nothing when clean" (§6) is the
        // human channel's contract; JSON that is sometimes absent is unparseable.
        let report = CheckReport {
            fail_on_warning: config.fail_on_warning,
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
            for weakening in weakenings {
                writeln!(out, "{}", weakening.line())?;
            }
            writeln!(
                out,
                "config-from {reference}: {} weakened",
                weakenings.len()
            )?;
        }
        for finding in &findings {
            // Pointer only: location and the rule that fired, never the line
            // text. A rule-scoped finding (no line) prints its pointer without
            // one rather than inventing a line number it does not have.
            match finding.line {
                Some(line) => writeln!(out, "{}:{} {}", finding.path, line, finding.rule)?,
                None => writeln!(out, "{} {}", finding.path, finding.rule)?,
            }
        }
    }
    // The severity axis reaches the exit contract exactly here: blocking is
    // derived through the taxonomy table, never name-matched (CLOUD-168), and
    // the two-valued outcome becomes a code in one place (§7).
    Ok(ExitCode::verdict(rules::any_blocking(
        &findings,
        config.fail_on_warning,
    )))
}

fn run_config(
    command: &ConfigCommand,
    overrides: &Overrides,
    out: &mut dyn Write,
) -> Result<ExitCode> {
    match command {
        ConfigCommand::Show => {
            let config = resolve::resolve(Path::new("."), overrides)?;
            // stdout is the answer: byte-stable JSON of the effective config,
            // with the layer that won each key alongside it (§8).
            let json = serde_json::to_string_pretty(&config)?;
            writeln!(out, "{json}")?;
            Ok(ExitCode::Success)
        }
        // The alarm beside `--config-from`'s control (CLOUD-87): a smell is a
        // verdict about the *config*, so any smell is a Violation — the same
        // code a rule finding returns, because it is the same kind of answer.
        // An unparseable config is a Usage error, raised by the loader.
        ConfigCommand::Lint => {
            let smells = lint::run(Path::new("."), overrides.config_from.as_deref())?;
            for smell in &smells {
                writeln!(out, "{}", smell.line_text())?;
            }
            // The count is stated even at zero: silence would be
            // indistinguishable from "the lint did not run".
            writeln!(out, "config-lint: {} smell(s)", smells.len())?;
            Ok(ExitCode::verdict(!smells.is_empty()))
        }
    }
}

fn run_spec(format: SpecFormat, out: &mut dyn Write) -> Result<ExitCode> {
    let described = spec::describe(&surface::command());
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
/// binary does not have — which is the property `completions-check` gates.
fn run_generate(command: &GenerateCommand, out: &mut dyn Write) -> Result<ExitCode> {
    match command {
        GenerateCommand::Completions { shell } => {
            clap_complete::generate(*shell, &mut surface::command(), "batten", out);
        }
        GenerateCommand::Schema => writeln!(out, "{}", config::schema()?)?,
    }
    Ok(ExitCode::Success)
}
