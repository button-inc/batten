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

use crate::Result;
use crate::error::UsageError;
use crate::exec::{Diagnostics, piped_argv};

/// What a probe command answered: its exit status and its combined output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ran {
    /// The command's own exit status.
    pub status: i32,
    /// Its stdout then its stderr, as text.
    pub log: String,
}

/// Run `command` to completion in the working directory, capturing both
/// streams.
///
/// # Through the placed adapter, never a spawn of its own
///
/// `policy/spawn-adapters.rego` places every spawn in the crate, and its table
/// refuses a new row: this module is not an adapter, so the command goes
/// through [`piped_argv`], the one argv spawn `exec` owns. The first word is a
/// NAME the resolution ladder resolves, which is what a caller's `--` argv is.
/// [`Diagnostics::Keep`] folds stderr in after stdout, because the harness line
/// that decides the reading may be on either stream.
///
/// # Errors
///
/// A [`UsageError`] for an empty command, and an internal error (exit `3`,
/// could-not-look) for a program that will not start or that ended without an
/// exit code, since a signal is no reading of the probe.
pub fn run(command: &[String]) -> Result<Ran> {
    let Some(program) = command.first() else {
        return Err(UsageError::raise(
            "record probe: the command to run follows `--`",
        ));
    };
    let root = std::env::current_dir()
        .map_err(|_| anyhow::anyhow!("record probe: the working directory is unreadable"))?;
    let (status, log) = piped_argv(&root, command, "", Diagnostics::Keep, &[]).ok_or_else(|| {
        anyhow::anyhow!(
            "record probe: `{program}` would not start or ended without an exit code, so there is no reading"
        )
    })?;
    Ok(Ran { status, log })
}

//MUTANT-SUITE crates/batten/tests/it/evaluator_io_probe.rs
//MUTANT status-not-carried|s@^    Ok(Ran { status, log })$@    Ok(Ran { status: 0, log })@|the_probe_verb_derives_a_real_failure_into_the_pass
//MUTANT stderr-not-read|s@Diagnostics::Keep, &\[\]@Diagnostics::Drop, \&[]@|the_probe_verb_reads_the_harness_line_on_either_stream
