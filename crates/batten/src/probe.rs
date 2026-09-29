//! Run a producer's probe command and hand back what a reading takes from it
//! (CLOUD-843, retiring `[tasks.evaluator-io-record]`).
//!
//! # Why the spawn moved in
//!
//! The task ran a probe build, captured its exit status and its output into a
//! temporary file, and piped the file to `record derive` with the status as an
//! input. Every step of that was shell glue around one reading the engine
//! already owns ([`crate::probe_verdict`]). `record probe` takes the command as
//! an argv after `--`, runs it, and derives the family's reading from its exit
//! status and its combined output, so the glue is gone and no body remains.
//!
//! The command is the CALLER's, which is why the verb is `unclassified` (house
//! style §5): what a probe does cannot be known from the row.
//!
//! # Pointer-only (non-negotiable rule 4)
//!
//! The output is held in memory for the reading and never printed, stored or
//! quoted in an error: a build log is the likeliest place in a producer for a
//! module body or a secret to appear.

use std::process::Stdio;

use crate::Result;
use crate::error::UsageError;

/// What a probe command answered: its exit status and its combined output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// The exit status, or `-1` for a command a signal ended.
    pub status: i32,
    /// Its stdout then its stderr, as text.
    pub log: String,
}

/// Run `command` to completion, capturing both streams.
///
/// # Errors
///
/// A [`UsageError`] for an empty command, and an internal error (exit `3`,
/// could-not-look) for a program that will not start.
pub fn run(command: &[String]) -> Result<Ran> {
    let Some((program, arguments)) = command.split_first() else {
        return Err(UsageError::raise(
            "record probe: the command to run follows `--`",
        ));
    };
    #[expect(
        clippy::disallowed_types,
        reason = "stays: running the caller's probe command IS this verb's effect, declared `unclassified` on its surface row (CLOUD-843)"
    )]
    let spawned = std::process::Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    let output = spawned.map_err(|_| {
        anyhow::anyhow!("record probe: `{program}` would not start, so there is no reading")
    })?;
    let mut log = String::from_utf8_lossy(&output.stdout).into_owned();
    // A stream that ends mid-line must not fuse its last line with the other's
    // first: the harness summary is read anchored at column 0.
    if !log.is_empty() && !log.ends_with('\n') {
        log.push('\n');
    }
    log.push_str(&String::from_utf8_lossy(&output.stderr));
    Ok(Ran {
        status: output.status.code().unwrap_or(-1),
        log,
    })
}

//MUTANT-SUITE crates/batten/tests/it/evaluator_io_probe.rs
//MUTANT status-not-carried|s@^        status: output.status.code().unwrap_or(-1),$@        status: 0,@|the_probe_verb_derives_a_real_failure_into_the_pass
//MUTANT stderr-not-read|s@^    log.push_str(&String::from_utf8_lossy(&output.stderr));$@@|the_probe_verb_reads_the_harness_line_on_either_stream
