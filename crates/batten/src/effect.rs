//! The effect model (house-style §5).
//!
//! Every command self-declares an effect — `read`, `write`, or `destructive` —
//! and the classification lives in **one table keyed by the full command path**,
//! not scattered across the command definitions, because a safety classification
//! is far easier to review as a single list.
//!
//! Two invariants make the model fail-safe:
//!
//! * **Absence means "ask", never "safe".** A path missing from the table is
//!   unknown ([`Effect::Ask`]); the conservative reading is to prompt/deny, never
//!   to silently treat it as [`Effect::Read`].
//! * **User-supplied code is unclassifiable.** A command that runs an arbitrary
//!   passed command is listed [`Effect::Unclassified`] with a stated reason, not
//!   guessed.
//!
//! The agent read-only allowlist is *derived* from this table
//! (`filter(effect == read)`); there is never a second, hand-maintained list.

use std::collections::BTreeMap;

use serde::{Serialize, Serializer};

/// The declared effect of a command, keyed by its full path in [`table`].
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

/// The single classification table, keyed by full command path (root-relative,
/// so `config show`, never `batten config show`). This is the one reviewed list
/// the emitted spec and the derived allowlist both read from; a command grows an
/// entry here in the same change that adds it to the surface.
fn table() -> BTreeMap<&'static str, Effect> {
    BTreeMap::from([
        // `check` only inspects the tree and reports findings; it mutates
        // nothing. It refuses to run any rule kind that spawns a process
        // (`rules::run_static`), which is what keeps this `read` honest and
        // this path off the process-spawning surface.
        ("check", Effect::Read),
        ("config", Effect::Read),
        // `enforce` runs rule kinds that execute commands declared in
        // `batten.toml`. Per §5 a command that runs user-supplied code is
        // listed unclassified with a stated reason, never guessed — so it is
        // excluded from the derived read-only allowlist by construction.
        ("enforce", Effect::Unclassified),
        ("config show", Effect::Read),
        ("spec", Effect::Read),
        // `hook` adjudicates another tool's call: its own execution only reads
        // stdin and config, but its *decision* mediates writes, so it is listed
        // unclassified rather than allowed to leak into the derived read-only
        // allowlist (CLOUD-202).
        ("hook", Effect::Unclassified),
    ])
}

/// Resolve the declared effect for a full command path.
///
/// A path absent from [`table`] resolves to [`Effect::Ask`] — the conservative
/// reading required by §5 — never silently to [`Effect::Read`].
#[must_use]
pub fn effect_for(path: &str) -> Effect {
    table().get(path).copied().unwrap_or(Effect::Ask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_path_resolves_to_its_declared_effect() {
        assert_eq!(effect_for("spec"), Effect::Read);
    }

    #[test]
    fn unknown_path_is_ask_never_read() {
        // The load-bearing fail-safe: an unclassified path must not be read-only.
        let effect = effect_for("some-command-not-in-the-table");
        assert_eq!(effect, Effect::Ask);
        assert!(!effect.is_read_only());
    }

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
