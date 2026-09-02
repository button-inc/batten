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

/// A wrapped command's own exit code, travelling to the boundary that reports it.
///
/// **Not a failure, and not Batten's answer.** `batten exec` is a transparent
/// passthrough (CLOUD-285): the code belongs to the child, so it is neither a
/// policy verdict nor a statement about the invocation, and it is deliberately
/// outside [`crate::ExitCode`]'s table. That table stays total over the four codes
/// Batten *chooses*; this type is how a code Batten did not choose reaches the
/// process without pretending to be one of them.
///
/// It rides the error channel for the same reason [`Denial`] does — the library
/// never exits a process — and the boundary maps it to the child's code with no
/// output of its own.
///
/// The property that matters is preserved: **Batten never mints a `2` here.** A
/// `2` from `exec` is the child's. Mediated calls are adjudicated by
/// [`crate::hook`], never by this path, so nothing reads an `exec` code as a deny.
#[derive(Debug)]
pub struct Passthrough(pub i32);

impl fmt::Display for Passthrough {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the wrapped command exited {}", self.0)
    }
}

impl std::error::Error for Passthrough {}

impl Passthrough {
    /// Build a [`Passthrough`] as an [`anyhow::Error`], ready to `return Err(..)`.
    #[must_use]
    pub fn raise(code: i32) -> anyhow::Error {
        anyhow::Error::new(Passthrough(code))
    }

    /// The byte a process exit status can actually carry.
    ///
    /// Saturates rather than truncating. A code outside one byte can only come
    /// from a non-POSIX child, and taking its low byte could turn a failure into a
    /// success — `0x100` would report `0`. Saturating keeps a non-zero code
    /// non-zero, which is the only property a caller can act on.
    #[must_use]
    pub fn byte(&self) -> u8 {
        u8::try_from(self.0).unwrap_or(u8::MAX)
    }
}

/// An expected bad-input error that maps to [`ExitCode::Usage`] (exit `1`).
///
/// # The class is a field, not a formatted prefix
///
/// CLOUD-1050's measured lesson is that a refusal carried as a free `String`
/// makes a bad refusal **expressible and uncheckable** — that is why a policy
/// `violation` binds `{rule, verdict, subjects}` and has no `msg`. The
/// config-load surface had the same defect: ~172 `raise` sites, none naming a
/// class, so `batten policy explain` could not resolve a config fault and no
/// gate held one to the `[[verdict]]` registry (CLOUD-1313).
///
/// Formatting a token into the message would have reproduced that defect one
/// surface over, because nothing would check that the token is declared.
/// [`Native`] is an enum, so a raise site can only name a class that exists,
/// and `the_vendored_table_validates` proves every variant carries a row.
///
/// [`ExitCode::Usage`]: crate::ExitCode::Usage
/// [`Native`]: crate::verdict::Native
#[derive(Debug)]
pub struct UsageError {
    /// The prose. Unchanged from the pre-class shape, deliberately: rewording
    /// the twelve validators' refusals is explicitly outside CLOUD-1313.
    pub message: String,
    /// The declared class this fault belongs to, where one is known.
    ///
    /// `None` is not a gap to be closed everywhere — most `UsageError`s are
    /// argument faults, not config faults, and inventing a class for each would
    /// be the per-site explosion CLOUD-1313 rejected. It is `Some` exactly where
    /// a raiser can name the table it was validating.
    pub verdict: Option<crate::verdict::Native>,
}

impl fmt::Display for UsageError {
    /// `<class>: <message>` when a class is known, the bare message otherwise.
    ///
    /// The separator is a deliberate deviation from CLOUD-1286's
    /// `<class> <pointer…>`, and the reason is that these messages are PROSE.
    /// That shape reads as a class followed by pointers precisely because
    /// nothing separates them; running a class straight into a sentence would
    /// make the first three words of the sentence look like part of the class.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.verdict {
            Some(native) => write!(f, "{}: {}", native.id(), self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for UsageError {}

impl UsageError {
    /// Build a classless [`UsageError`] as an [`anyhow::Error`], ready to
    /// `return Err(..)`.
    ///
    /// Named `raise` rather than `new` because it returns an [`anyhow::Error`]
    /// wrapping the `UsageError`, not `Self`.
    pub fn raise(message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(UsageError {
            message: message.into(),
            verdict: None,
        })
    }

    /// Build a [`UsageError`] that names the class it belongs to.
    ///
    /// Callers are the config loader's per-table wrappers; see
    /// [`crate::config`]'s `under`.
    pub fn raise_as(verdict: crate::verdict::Native, message: impl Into<String>) -> anyhow::Error {
        anyhow::Error::new(UsageError {
            message: message.into(),
            verdict: Some(verdict),
        })
    }
}
