//! What an agent can do in THIS repository, derived live (CLOUD-1180).
//!
//! CLOUD-19's directive — *"the agent-first preset work adds a new top-level
//! `agent` subtree. Amend house-style §2 and runtime `SURFACE` together, with an
//! explicit effect on every full command path, so this does not create a second
//! command authority"* — survived only as a comment on a closed issue, and
//! nothing of it survived in the tree at all. This is the first landable slice of
//! it: the leaf that reads what already ships.
//!
//! ## The spelling is `show agent`, and that is a departure the row records
//!
//! CLOUD-1180's original leaf table said `agent instructions`. Its own 2026-08-30
//! amendment respells that to `show agent` under CLOUD-1184's imperative
//! `VERB OBJECT` grammar, where **the verb carries the effect band**. Both
//! CLOUD-1184 (the grammar) and CLOUD-1179 (the §2 reconciliation) are landed, so
//! the amendment governs.
//!
//! The precedent is in the tree rather than in this reasoning: `record <object>`
//! is already spelled that way, and says why at its own row — *"a `tool record`
//! added today would be a third row to invert; this spelling is already the
//! target. The transitional inconsistency is real, and it is the cost of not
//! growing the backlog."* Adding `agent instructions` today would be one more row
//! for CLOUD-1190 to invert.
//!
//! ## Nothing here is a second authority
//!
//! That is the directive's actual constraint, and it is what bounds the content.
//! Every field below is **derived from a model that already exists** and none is
//! restated:
//!
//! * the read-only allowlist comes from [`crate::spec::read_only_allowlist`], the
//!   one implementation of §5's `effect == read` filter — re-deriving it here
//!   would be a second place for the safety-critical derivation to be wrong, in
//!   the unsafe direction;
//! * the exit table comes from [`crate::exit::ExitCode::ALL`] and each code's own
//!   `meaning()`, so a code cannot mean one thing here and another there;
//! * the gate inventory comes from the resolved [`crate::resolve::Resolved`]'s
//!   own rules, after §8 layering — so what is reported is what would actually
//!   gate a call, never what the committed file alone says.
//!
//! ## Pointer, never payload (rule 4)
//!
//! A gate is reported as its **id and severity** — never its `glob`, its
//! `pattern`, or its `reason`. This verb exists to be read by an agent at the
//! start of a session, which makes it the likeliest surface here to be pasted
//! somewhere, and a rule's pattern is the consumer's own policy text.
//!
//! ## Absent config is a state, never an error — and never "nothing is gated"
//!
//! A repository with no `batten.toml` reports `configured: false` and exits `0`.
//! It is not a usage error: "no committed authority governs here" is a true and
//! useful answer to "what may I do here", and CLOUD-1180's §7(d) asks for exactly
//! that deterministic unavailable state.
//!
//! **`configured: false` does NOT mean the gate list is empty, and an earlier
//! draft of this module said it did.** `resolve` succeeds with the BUILT-IN
//! DEFAULTS where no authority exists, and those defaults really do gate the
//! tree — `config::ABSENT_NOTICE` is the standing statement of it: *"the built-in
//! defaults are what just gated your tree, and here is how to state your own."*
//! Reporting `gates: []` there would tell an agent it may do anything, which is
//! the one direction this verb must never be wrong in. So the two keys answer two
//! questions: `configured` says whether the repository STATES a policy, `gates`
//! says what is actually IN FORCE. An integration test over a fixture with no
//! config is what caught the draft that conflated them.

use serde::Serialize;

use crate::config::Authority;
use crate::exit::ExitCode;
use crate::output::Line;
use crate::resolve::Resolved;
use crate::spec::{self, ReadOnlyEntry, SPEC_VERSION};
use crate::surface;

/// One exit code and the meaning it carries, projected from [`ExitCode`].
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ExitMeaning {
    /// The numeric value a caller branches on.
    pub code: i32,
    /// The §7 meaning, taken from [`ExitCode::meaning`] rather than retyped.
    pub meaning: &'static str,
}

/// One declared gate, as a pointer to it.
///
/// `id` and `severity` and nothing else: see the module doc's rule-4 note.
#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Gate {
    /// The rule's declared id.
    pub id: String,
    /// The severity token, or `"default"` where the row declares none — an
    /// absent severity is a real state (the rule takes the engine's default) and
    /// collapsing it into `deny` would overstate what the consumer wrote.
    pub severity: String,
}

/// What an agent may do in this repository.
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Capabilities {
    /// The shape of this document, shared with `batten spec` so one consumer
    /// version-check covers both.
    pub spec_version: u32,
    /// Whether a committed `batten.toml` governs this repository.
    ///
    /// Read from [`Authority`] rather than from whether a `Resolved` was
    /// obtained, and the distinction is the point: `resolve` succeeds with the
    /// built-in defaults where no authority exists, so "I got a config" and
    /// "this repository states a policy" are different questions and only the
    /// second is what an agent is asking. `false` is an answer, not a failure.
    pub configured: bool,
    /// Every verb §5 classifies as read-only, and therefore safe to run
    /// unprompted. Derived, never re-filtered here.
    pub read_only: Vec<ReadOnlyEntry>,
    /// The §7 exit contract, so a caller branches on documented values.
    pub exit_codes: Vec<ExitMeaning>,
    /// The gates this repository declares, as pointers.
    pub gates: Vec<Gate>,
}

/// Read this repository's capabilities.
///
/// Takes the already-resolved config rather than resolving one, which is what
/// keeps this function pure and the verb `read`: there is no path from here to
/// the filesystem, so `show agent` cannot become a writer by accident.
#[must_use]
pub fn capabilities(resolved: Option<&Resolved>) -> Capabilities {
    let mut gates: Vec<Gate> = resolved
        .map(|resolved| {
            resolved
                .rules
                .iter()
                .map(|rule| Gate {
                    id: rule.id.clone(),
                    severity: rule
                        .severity
                        .map_or_else(|| String::from("default"), |sev| sev.as_str().to_owned()),
                })
                .collect()
        })
        .unwrap_or_default();
    // Sorted, so the document is a function of what is declared rather than
    // of the order it was typed in (§6 byte-stability).
    gates.sort();

    Capabilities {
        spec_version: SPEC_VERSION,
        configured: resolved.is_some_and(|resolved| resolved.authority == Authority::Present),
        read_only: spec::read_only_allowlist(&spec::describe(&surface::command())),
        exit_codes: ExitCode::ALL
            .iter()
            .map(|code| ExitMeaning {
                code: code.code(),
                meaning: code.meaning(),
            })
            .collect(),
        gates,
    }
}

impl Line for ExitMeaning {
    fn line(&self) -> String {
        format!("exit {} {}", self.code, self.meaning)
    }
}

impl Line for ReadOnlyEntry {
    fn line(&self) -> String {
        format!("read-only {} {}", self.id, self.path)
    }
}

impl Line for Gate {
    fn line(&self) -> String {
        format!("gate {} {}", self.id, self.severity)
    }
}

impl Capabilities {
    /// The trailing count line.
    ///
    /// Stated even at zero, on `config lint`'s reasoning: silence would be
    /// indistinguishable from "the verb did not run".
    #[must_use]
    pub fn summary(&self) -> String {
        format!(
            "agent: {} read-only verb(s), {} gate(s), {}",
            self.read_only.len(),
            self.gates.len(),
            if self.configured {
                "from this repository's batten.toml"
            } else {
                // NEVER "nothing is gated": the defaults are in force and the
                // count above is theirs. See the module doc.
                "from the built-in defaults — no batten.toml states a policy here"
            }
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn an_unresolvable_repository_is_a_state_rather_than_an_error() {
        // CLOUD-1180 §7(d), for the arm where nothing resolved AT ALL — outside a
        // repository, say. That is a different case from "resolved to the
        // built-in defaults", which reports `configured: false` with a NON-empty
        // gate list; `agent_capabilities::an_unconfigured_repository_...` covers
        // that one over the compiled binary, and the two must not be collapsed:
        // saying "nothing is gated" where the defaults are gating is the one
        // direction this verb must never be wrong in.
        let reading = capabilities(None);
        assert!(!reading.configured);
        assert!(reading.gates.is_empty());
        // The read-only allowlist is a property of the BINARY, not of the
        // repository, so it is populated even here. That is the discriminating
        // half: an implementation that returned a wholly empty document for the
        // absent case would pass a `gates.is_empty()` check and be wrong.
        assert!(
            !reading.read_only.is_empty(),
            "the allowlist comes from the surface and does not depend on config"
        );
        assert!(reading.summary().contains("built-in defaults"));
    }

    #[test]
    fn the_reading_is_byte_stable_across_two_calls() {
        // §6. No clock, no filesystem, no map iteration order reaches the
        // document, so two calls over one input are identical.
        let first = serde_json::to_string(&capabilities(None)).unwrap();
        let second = serde_json::to_string(&capabilities(None)).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn the_exit_table_is_derived_rather_than_retyped() {
        // Fails by: hand-writing the table here. Every code the binary can mint
        // appears, carrying that code's own `meaning()`.
        let reading = capabilities(None);
        assert_eq!(reading.exit_codes.len(), ExitCode::ALL.len());
        for code in ExitCode::ALL {
            let row = reading
                .exit_codes
                .iter()
                .find(|row| row.code == code.code())
                .expect("every code is projected");
            assert_eq!(row.meaning, code.meaning());
        }
    }

    #[test]
    fn a_gate_is_a_pointer_and_never_its_pattern() {
        // Rule 4, asserted on the type rather than on one rendering: `Gate` has
        // two fields and neither can hold a glob, a pattern or a reason. A field
        // added later that could fails this by construction.
        let gate = Gate {
            id: String::from("no-secrets"),
            severity: String::from("deny"),
        };
        assert_eq!(gate.line(), "gate no-secrets deny");
        let json = serde_json::to_string(&gate).unwrap();
        assert_eq!(json, r#"{"id":"no-secrets","severity":"deny"}"#);
    }
}
