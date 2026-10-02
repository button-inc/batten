//! `batten ci step`: the glue a workflow step used a shell for, as one argv.
//!
//! # What it retires
//!
//! A workflow `run:` step was shell for four reasons, measured over this
//! repository's workflows (CLOUD-843, Phase 4). None of them is a decision, so
//! none belongs in rego. Each one is the runner's own file contract:
//!
//! * **`>>"$GITHUB_OUTPUT"`** — a command printing `KEY=VALUE` lines whose
//!   output later steps read. `--outputs` appends those lines to the file the
//!   runner names.
//! * **`{ echo '## Title'; cat log; } >>"$GITHUB_STEP_SUMMARY"`** — a report
//!   fenced into the run's summary, usually by a second step reading a file the
//!   first one redirected into. `--summary <title>` writes it from the run
//!   itself, so the file and the second step both go.
//! * **`set +e; cmd; case $? in 0) echo x=a ;; 2) echo x=b ;; *) exit $? ;; esac`**
//!   — a verdict mapped to an output. `--verdict <key>` with repeated
//!   `--on <code>=<value>` rows writes `KEY=VALUE` for a mapped code and exits
//!   `0`; an unmapped code is the command's own, unchanged.
//! * **`cmd >file` and `cmd <file`** — a capture a later step reads.
//!   `--save <path>` and `--stdin <path>` are those two, with the path
//!   relative to where the step stands.
//! * **`echo "sha=$(git merge-base origin/main HEAD)" >>"$GITHUB_OUTPUT"`** — a
//!   bare answer captured under a key. `--capture <key>` writes `KEY=` and the
//!   first line of the command's stdout, trimmed, or nothing after the `=` when
//!   it printed none.
//! * **`if [ -z "$SECRET" ]; then echo ::error::…; exit 1; fi`** — a credential
//!   that must not be empty. `--require-env <NAME>` refuses the step before the
//!   command runs when the variable is unset or empty, naming the variable and
//!   NEVER its value.
//! * **`cmd "$TAG" "${{ steps.x.outputs.y }}"`** — a value handed to the
//!   command through the step's `env:`. `--arg-env <NAME>` appends that
//!   variable's value as ONE argument, in the order written, with no word
//!   splitting and no glob. An unset or empty variable is a usage error, where
//!   the shell would have passed an empty word and let the command guess.
//!
//! # The contract is the runner's, and it is generic
//!
//! `GITHUB_OUTPUT` and `GITHUB_STEP_SUMMARY` are the runner's variable names,
//! not a consumer's; the verb names no workflow, job or repository (rule 1).
//! Outside a runner, where neither is set, every line still reaches stdout and
//! the verb writes nothing else. That is the reading a local rehearsal needs:
//! the same command, the same output, and no file anyone has to clean up.
//!
//! # The command's verdict is the verb's
//!
//! A child's `2` stays `2` unless `--on 2=…` maps it. The glue never turns a
//! failure into a pass by accident: a summary or output file that will not take
//! a write is an error, because a step whose outputs were lost is a step whose
//! readers will act on nothing.

use std::io::Write;

use anyhow::{Context as _, Result, anyhow};

use crate::error::UsageError;
use crate::exit::ExitCode;

/// The runner's file for step outputs.
pub const OUTPUT_VAR: &str = "GITHUB_OUTPUT";

/// The runner's file for the run summary.
pub const SUMMARY_VAR: &str = "GITHUB_STEP_SUMMARY";

/// How many trailing lines a summary keeps, so a long log does not bury the
/// run page. The whole log is still in the step's own output.
pub const SUMMARY_TAIL: usize = 200;

/// One `batten ci step` invocation, parsed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct StepRequest {
    /// Append the command's `KEY=VALUE` stdout lines to the output file.
    pub outputs: bool,
    /// Fence the command's output into the run summary under this title.
    pub summary: Option<String>,
    /// Write the command's stdout to this path as well.
    pub save: Option<String>,
    /// Feed this file to the command's stdin.
    pub stdin: Option<String>,
    /// The output key a mapped exit code is written under.
    pub verdict: Option<String>,
    /// `code=value` rows mapping an exit code to the verdict's value.
    pub on: Vec<String>,
    /// Variables whose values are appended to the command, one argument each.
    pub arg_env: Vec<String>,
    /// The output key the first stdout line is captured under.
    pub capture: Option<String>,
    /// Variables that must be set and non-empty before the command runs.
    pub require_env: Vec<String>,
    /// The command, verbatim. Never empty — the surface requires it.
    pub command: Vec<String>,
}

/// A step output line: `KEY=VALUE`, with a key the runner accepts.
#[must_use]
pub fn output_line(line: &str) -> bool {
    let Some((key, _)) = line.split_once('=') else {
        return false;
    };
    let mut chars = key.chars();
    chars
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The `--on` rows as `(code, value)`, refusing a malformed row as a usage
/// error rather than dropping it: a mapping that silently lost a row would
/// fail a step its author declared a pass.
///
/// # Errors
///
/// A [`UsageError`] naming the first row that is not `<integer>=<value>`.
pub fn mapping(rows: &[String]) -> Result<Vec<(i32, String)>> {
    rows.iter()
        .map(|row| {
            row.split_once('=')
                .and_then(|(code, value)| {
                    code.trim()
                        .parse::<i32>()
                        .ok()
                        .map(|code| (code, value.to_owned()))
                })
                .ok_or_else(|| {
                    UsageError::raise(format!("ci step: --on {row:?} is not <exit code>=<value>"))
                })
        })
        .collect()
}

/// The first required variable that is unset or empty, by name.
#[must_use]
pub fn missing(names: &[String], lookup: impl Fn(&str) -> Option<String>) -> Option<&str> {
    names
        .iter()
        .find(|name| lookup(name).is_none_or(|value| value.is_empty()))
        .map(String::as_str)
}

/// The command with each `--arg-env` variable's value appended, in order.
///
/// # Errors
///
/// A [`UsageError`] naming the first variable that is unset or empty.
pub fn argv(
    command: &[String],
    names: &[String],
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<Vec<String>> {
    let mut argv = command.to_vec();
    for name in names {
        match lookup(name).filter(|value| !value.is_empty()) {
            Some(value) => argv.push(value),
            None => {
                return Err(UsageError::raise(format!(
                    "ci step: --arg-env {name} names a variable that is unset or empty"
                )));
            }
        }
    }
    Ok(argv)
}

/// The `KEY=VALUE` line a capture writes: the first non-blank stdout line,
/// trimmed, or an empty value.
#[must_use]
pub fn captured(key: &str, stdout: &str) -> String {
    let value = stdout
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    format!("{key}={value}\n")
}

/// The summary section: a title and the fenced tail of the output.
#[must_use]
pub fn summary_section(title: &str, output: &str) -> String {
    let lines: Vec<&str> = output.lines().collect();
    let tail = lines
        .get(lines.len().saturating_sub(SUMMARY_TAIL)..)
        .unwrap_or_default();
    let mut section = format!("## {title}\n\n```\n");
    for line in tail {
        section.push_str(line);
        section.push('\n');
    }
    section.push_str("```\n");
    section
}

/// Append `text` to the file the runner variable `var` names, if it names one.
///
/// Through [`crate::durable::append`] (CLOUD-1919): one write and a sync, so a
/// crash leaves the runner's file with the lines whole or absent, never torn. An
/// empty text writes nothing, because the durable append would supply a newline
/// and put a blank line into a file the runner parses.
fn append_to(var: &str, text: &str) -> Result<()> {
    let Some(path) = std::env::var_os(var).filter(|path| !path.is_empty()) else {
        return Ok(());
    };
    if text.is_empty() {
        return Ok(());
    }
    crate::durable::append(std::path::Path::new(&path), text)
        .with_context(|| format!("ci step: write ${var}"))
}

/// Run the command, tee its output, and do the glue the request names.
///
/// # Errors
///
/// A [`UsageError`] for an empty command, a malformed `--on` row, or a command
/// that cannot be started; a [`crate::Passthrough`] carrying an unmapped
/// non-zero code; an I/O error when an output, summary or save file will not
/// take its write.
pub fn run(request: &StepRequest, out: &mut dyn Write, err: &mut dyn Write) -> Result<ExitCode> {
    let map = mapping(&request.on)?;
    if !map.is_empty() && request.verdict.is_none() {
        return Err(UsageError::raise(
            "ci step: --on maps a code to a value, and needs --verdict to name its key",
        ));
    }
    if let Some(name) = missing(&request.require_env, |name| std::env::var(name).ok()) {
        writeln!(
            err,
            "::error:: ci step: {name} is unset or empty, and this step requires it"
        )?;
        return Ok(ExitCode::Violation);
    }
    let command = argv(&request.command, &request.arg_env, |name| {
        std::env::var(name).ok()
    })?;
    let Some(program) = command.first() else {
        return Err(UsageError::raise("ci step: no command after `--`"));
    };
    let stdin = match request.stdin {
        Some(ref path) => std::fs::read_to_string(path)
            .map_err(|e| UsageError::raise(format!("ci step: --stdin {path}: {e}")))?,
        None => String::new(),
    };
    // THROUGH `exec`'s ONE SHARED SPAWN, so this verb adds no spawn escape of its
    // own (`spawn add other`, CLOUD-1338). STDOUT IS CAPTURED because it is
    // PARSED — output lines, a capture, a saved file — and STDERR PASSES STRAIGHT
    // THROUGH to the runner's log, so a failing build's diagnostics are visible
    // as they arrive and never fold into a value a later step reads. The cost,
    // stated: stdout is echoed once the command finishes rather than line by line.
    let (code, stdout) = crate::exec::piped_argv(
        std::path::Path::new("."),
        &command,
        &stdin,
        crate::exec::Diagnostics::Pass,
        &[],
    )
    .ok_or_else(|| {
        UsageError::raise(format!(
            "ci step: {program} could not be started, or died without an exit code"
        ))
    })?;
    write!(out, "{stdout}")?;
    // Stderr passed through to the runner's log unread, so the summary carries
    // stdout, which is where a report is written.
    let stderr = String::new();

    if let Some(ref path) = request.save {
        crate::durable::replace(path, &stdout)
            .with_context(|| format!("ci step: --save {path}"))?;
    }
    if request.outputs {
        let mut lines = String::new();
        for line in stdout.lines().filter(|line| output_line(line)) {
            lines.push_str(line);
            lines.push('\n');
        }
        append_to(OUTPUT_VAR, &lines)?;
    }
    if let Some(ref key) = request.capture {
        append_to(OUTPUT_VAR, &captured(key, &stdout))?;
    }
    if let Some(ref title) = request.summary {
        append_to(
            SUMMARY_VAR,
            &summary_section(title, &format!("{stdout}{stderr}")),
        )?;
    }
    if let Some(ref key) = request.verdict
        && let Some((_, value)) = map.iter().find(|(mapped, _)| *mapped == code)
    {
        writeln!(err, "ci step: exit {code} -> {key}={value}")?;
        append_to(OUTPUT_VAR, &format!("{key}={value}\n"))?;
        return Ok(ExitCode::Success);
    }
    if code == 0 {
        return Ok(ExitCode::Success);
    }
    Err(anyhow!(crate::Passthrough(code)))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
//MUTANT-SUITE crates/batten/src/ci_step.rs
//MUTANT key-unchecked|s@        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')@        \&\& true@|only_a_key_value_line_is_an_output
//MUTANT tail-unbounded|s@lines.len().saturating_sub(SUMMARY_TAIL)@0@|a_summary_keeps_the_tail_of_a_long_log
//MUTANT empty-passed|s@        match lookup(name).filter(|value| !value.is_empty()) {@        match lookup(name) {@|an_env_argument_is_one_word_and_an_empty_one_is_refused
//MUTANT require-empty-passed|s@        .find(|name| lookup(name).is_none_or(|value| value.is_empty()))@        .find(|name| lookup(name).is_none())@|a_required_variable_must_be_set_and_non_empty
//MUTANT capture-blank|s@        .find(|line| !line.is_empty())@        .next()@|a_capture_is_the_first_non_blank_line_or_empty
mod tests {
    use super::*;

    #[test]
    fn only_a_key_value_line_is_an_output() {
        assert!(output_line("archive=target/x.tar.gz"));
        assert!(output_line("_x-y=1"));
        assert!(output_line("k="));
        assert!(!output_line("Compiling batten v0.1"));
        assert!(!output_line("=value"));
        assert!(!output_line("1key=value"));
        assert!(!output_line("a key=value"));
        assert!(!output_line("warning: x=y"));
    }

    #[test]
    fn a_mapping_row_is_a_code_and_a_value_or_a_usage_error() {
        let rows = vec!["0=green".to_owned(), "3=pending=later".to_owned()];
        assert_eq!(
            mapping(&rows).unwrap(),
            vec![(0, "green".to_owned()), (3, "pending=later".to_owned())]
        );
        assert!(mapping(&["green".to_owned()]).is_err());
        assert!(mapping(&["x=green".to_owned()]).is_err());
    }

    #[test]
    fn an_env_argument_is_one_word_and_an_empty_one_is_refused() {
        let command = vec!["gh".to_owned(), "release".to_owned()];
        let names = vec!["TAG".to_owned(), "FILE".to_owned()];
        let env = |name: &str| match name {
            "TAG" => Some("v1.0.0".to_owned()),
            "FILE" => Some("a b.tar.gz".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        assert_eq!(
            argv(&command, &names, env).unwrap(),
            vec!["gh", "release", "v1.0.0", "a b.tar.gz"]
        );
        assert!(argv(&command, &["EMPTY".to_owned()], env).is_err());
        assert!(argv(&command, &["UNSET".to_owned()], env).is_err());
    }

    #[test]
    fn a_required_variable_must_be_set_and_non_empty() {
        let env = |name: &str| match name {
            "SET" => Some("x".to_owned()),
            "EMPTY" => Some(String::new()),
            _ => None,
        };
        assert_eq!(missing(&["SET".to_owned()], env), None);
        assert_eq!(
            missing(&["SET".to_owned(), "EMPTY".to_owned()], env),
            Some("EMPTY")
        );
        assert_eq!(missing(&["UNSET".to_owned()], env), Some("UNSET"));
    }

    #[test]
    fn a_capture_is_the_first_non_blank_line_or_empty() {
        assert_eq!(captured("sha", "\n  abc123  \nother\n"), "sha=abc123\n");
        assert_eq!(captured("tag", ""), "tag=\n");
    }

    #[test]
    fn a_summary_keeps_the_tail_of_a_long_log() {
        let mut log = String::new();
        for i in 0..SUMMARY_TAIL + 5 {
            log.push_str("line ");
            log.push_str(&i.to_string());
            log.push('\n');
        }
        let section = summary_section("Report", &log);
        assert!(section.starts_with("## Report\n\n```\n"), "{section}");
        assert!(section.ends_with("```\n"), "{section}");
        assert!(!section.contains("line 4\n"), "the head is dropped");
        assert!(section.contains(&format!("line {}\n", SUMMARY_TAIL + 4)));
    }
}
