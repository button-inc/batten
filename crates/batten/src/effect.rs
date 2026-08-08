//! The effect vocabulary (house-style §5).
//!
//! Every command self-declares an effect — `read`, `write`, or `destructive` —
//! and the classification is carried on the command's own row in
//! [`crate::surface::SURFACE`], so a safety classification is reviewed as part
//! of the one list that declares the surface rather than in a second table
//! keyed by the same paths.
//!
//! This module owns the *vocabulary*; [`crate::surface::effect_for`] owns the
//! resolution, and the agent read-only allowlist is derived from the same walk
//! (`filter(effect == read)`). There is never a second, hand-maintained list.
//!
//! Two invariants make the model fail-safe, and both are enforced where a
//! command is declared:
//!
//! * **Absence means "ask", never "safe".** A path with no row is unknown
//!   ([`Effect::Ask`]); the conservative reading is to prompt/deny, never to
//!   silently treat it as [`Effect::Read`].
//! * **User-supplied code is unclassifiable.** A command that runs an arbitrary
//!   passed command is listed [`Effect::Unclassified`] with a stated reason, not
//!   guessed.

use serde::{Serialize, Serializer};

/// The declared effect of a command, carried on its [`crate::surface`] row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Inspection only; idempotent. Not running it changes nothing.
    Read,
    /// Creates or modifies state the caller can recreate.
    Write,
    /// Removes something whose recovery means redoing work.
    Destructive,
    /// Runs arbitrary user-supplied code, so its effect cannot be known ahead of
    /// time. Listed explicitly rather than guessed.
    Unclassified,
    /// Not present in the table: unknown, and read conservatively as "ask".
    Ask,
}

impl Effect {
    /// The stable lowercase token used in machine output.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Effect::Read => "read",
            Effect::Write => "write",
            Effect::Destructive => "destructive",
            Effect::Unclassified => "unclassified",
            Effect::Ask => "ask",
        }
    }

    /// Whether this effect qualifies a command for the derived read-only
    /// allowlist. Only [`Effect::Read`] does — every other value, `Ask`
    /// included, is excluded, which is what keeps the allowlist fail-safe.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        matches!(self, Effect::Read)
    }
}

impl Serialize for Effect {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_read_is_read_only() {
        assert!(Effect::Read.is_read_only());
        for effect in [
            Effect::Write,
            Effect::Destructive,
            Effect::Unclassified,
            Effect::Ask,
        ] {
            assert!(
                !effect.is_read_only(),
                "{} leaked into read-only",
                effect.as_str()
            );
        }
    }
}
