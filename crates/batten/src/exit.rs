//! The general exit-code contract.
//!
//! Batten's exit codes are part of its public interface: local shells, CI, and
//! agent hook adapters all branch on them, so they are defined once here and
//! documented in `doctor`'s exit-code table rather than scattered as literals.
//!
//! Note that the `hook` subcommand deliberately *inverts* part of this contract
//! so that exit `2` denies a mediated tool call; that inversion lives with the
//! hook layer, not here.

/// A process exit status with a stable, documented numeric value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    /// The check passed, or the command completed with nothing to report.
    Success = 0,
    /// A policy violation was found. The invocation itself was well-formed.
    Violation = 1,
    /// The invocation was malformed: bad flags, unreadable config, or usage error.
    Usage = 2,
    /// Batten could not complete the check (I/O failure, missing tool, internal error).
    Internal = 3,
}

impl ExitCode {
    /// The raw integer value handed to the operating system.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }
}

impl From<ExitCode> for std::process::ExitCode {
    fn from(value: ExitCode) -> Self {
        // ExitCode is constrained to the 0..=255 process-exit range, so this
        // conversion is total. Tie the out-of-range fallback to Internal's code
        // rather than a bare literal, so the two cannot silently drift apart.
        Self::from(u8::try_from(value.code()).unwrap_or(ExitCode::Internal as u8))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every documented variant, paired with its contracted numeric value (§7).
    /// The command-level table test (`tests/cli.rs`) asserts which *invocations*
    /// reach each code; this pins the codes themselves, including `Violation` and
    /// `Internal`, which no command reaches at this scaffold stage.
    const CONTRACT: [(ExitCode, i32); 4] = [
        (ExitCode::Success, 0),
        (ExitCode::Violation, 1),
        (ExitCode::Usage, 2),
        (ExitCode::Internal, 3),
    ];

    #[test]
    fn codes_match_the_documented_contract() {
        // The numeric values are public interface: a reorder or renumber must be
        // caught here rather than by a consumer branching on the wrong code.
        for (code, raw) in CONTRACT {
            assert_eq!(code.code(), raw, "{code:?} must map to exit {raw}");
        }
    }

    #[test]
    fn every_documented_code_fits_the_process_exit_range() {
        // The From<ExitCode> conversion falls back to Internal only for a code
        // outside 0..=255. Assert every variant fits, so that fallback is dead
        // code and the conversion never silently remaps a real code.
        for (code, _) in CONTRACT {
            assert!(u8::try_from(code.code()).is_ok(), "{code:?} must fit u8");
        }
    }
}
