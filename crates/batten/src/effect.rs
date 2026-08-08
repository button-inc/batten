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

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

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
    /// Every effect, so anything that ranges over the vocabulary is derived
    /// rather than re-typed — the parse in [`Effect::from_token`] and the
    /// coverage test both read this, so adding a variant cannot leave one of
    /// them behind.
    pub const ALL: &'static [Effect] = &[
        Effect::Read,
        Effect::Write,
        Effect::Destructive,
        Effect::Unclassified,
        Effect::Ask,
    ];

    /// The effect named by `token`, or `None` if it names none.
    ///
    /// Derived from [`Effect::ALL`] and [`Effect::as_str`], so the accepted
    /// spellings are exactly the emitted ones by construction.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Effect> {
        Effect::ALL
            .iter()
            .copied()
            .find(|effect| effect.as_str() == token)
    }

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

impl<'de> Deserialize<'de> for Effect {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let token = String::deserialize(deserializer)?;
        Effect::from_token(&token).ok_or_else(|| {
            let known: Vec<&str> = Effect::ALL.iter().map(|effect| effect.as_str()).collect();
            de::Error::custom(format!(
                "unknown effect {token:?}; expected one of {}",
                known.join(", ")
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_read_is_read_only() {
        // Derived from ALL rather than a re-typed list, so a variant added
        // without a decision about the allowlist fails here instead of
        // defaulting into it.
        assert!(Effect::Read.is_read_only());
        for effect in Effect::ALL.iter().copied().filter(|e| *e != Effect::Read) {
            assert!(
                !effect.is_read_only(),
                "{} leaked into read-only",
                effect.as_str()
            );
        }
    }

    #[test]
    fn every_effect_round_trips_through_its_token() {
        // The vocabulary has one authority: what `as_str` emits is exactly what
        // `from_token` accepts, and `ALL` is what makes both total. A new
        // variant missing from `ALL` fails here rather than becoming a config
        // value nothing can parse.
        for effect in Effect::ALL.iter().copied() {
            assert_eq!(Effect::from_token(effect.as_str()), Some(effect));
        }
        assert_eq!(Effect::ALL.len(), 5, "add the new variant to ALL");
        assert_eq!(Effect::from_token("nonsense"), None);
        assert_eq!(Effect::from_token("Read"), None, "lowercase tokens only");
    }
}
