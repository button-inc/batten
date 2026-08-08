//! Typed errors that carry their intended process exit code.
//!
//! Most failures in the library are genuine internal errors ([`ExitCode::Internal`]).
//! A [`UsageError`] is different: it marks an *expected* bad-input condition —
//! a malformed config, an unknown key, an unsupported version — that the
//! exit-code contract (§7) maps to [`ExitCode::Usage`] (exit `1`), not to an
//! internal failure. The binary boundary downcasts to it to pick the code.
//!
//! [`Denial`] is not a failure at all: it is the mediation verdict travelling to
//! the one place allowed to write stderr. It rides the error channel because the
//! library never prints, and the boundary maps it to [`ExitCode::Violation`]
//! (exit `2`) — printing the reason *unprefixed*, since a verdict is an answer
//! and must not read as a crash.
//!
//! [`ExitCode::Internal`]: crate::ExitCode::Internal
//! [`ExitCode::Usage`]: crate::ExitCode::Usage
//! [`ExitCode::Violation`]: crate::ExitCode::Violation

use std::fmt;

/// A mediated call refused by policy: maps to [`ExitCode::Violation`] (exit `2`)
/// with the reason on stderr, which is what a hook host reads as the deny.
///
/// [`ExitCode::Violation`]: crate::ExitCode::Violation
#[derive(Debug)]
pub struct Denial(pub String);

impl fmt::Display for Denial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Denial {}

impl Denial {
    /// Build a [`Denial`] as an [`anyhow::Error`], ready to `return Err(..)`.
    ///
    /// Named `raise` for symmetry with [`UsageError::raise`]: it returns an
    /// [`anyhow::Error`] wrapping the `Denial`, not `Self`.
    pub fn raise(reason: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(Denial(reason.into()))
    }
}

/// An expected bad-input error that maps to [`ExitCode::Usage`] (exit `1`).
///
/// [`ExitCode::Usage`]: crate::ExitCode::Usage
#[derive(Debug)]
pub struct UsageError(pub String);

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for UsageError {}

impl UsageError {
    /// Build a [`UsageError`] as an [`anyhow::Error`], ready to `return Err(..)`.
    ///
    /// Named `raise` rather than `new` because it returns an [`anyhow::Error`]
    /// wrapping the `UsageError`, not `Self`.
    pub fn raise(message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(UsageError(message.into()))
    }
}
