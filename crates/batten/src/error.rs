//! A typed error that carries its intended process exit code.
//!
//! Most failures in the library are genuine internal errors ([`ExitCode::Internal`]).
//! A [`UsageError`] is different: it marks an *expected* bad-input condition —
//! a malformed config, an unknown key, an unsupported version — that the
//! exit-code contract (§7) maps to [`ExitCode::Usage`] (exit `2`), not to an
//! internal failure. The binary boundary downcasts to it to pick the code.
//!
//! [`ExitCode::Internal`]: crate::ExitCode::Internal
//! [`ExitCode::Usage`]: crate::ExitCode::Usage

use std::fmt;

/// An expected bad-input error that maps to [`ExitCode::Usage`] (exit `2`).
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
