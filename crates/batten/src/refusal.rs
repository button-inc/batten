//! The refusal contract (CLOUD-122): **every deny points to the fix.**
//!
//! One type, constructed at every deny site, projected onto whatever channel the
//! caller's host reads. Before this each deny site composed its own `format!` —
//! [`crate::hook`]'s shape rows, [`crate::hook`]'s derived protected-path gate,
//! and [`crate::rules::run_static`]'s refusal of a kind `check` cannot honestly
//! run — so "does this deny name a fix?" was a property of prose, and a fourth
//! deny site could land carrying a bare "no" with every gate green.
//!
//! Three choices carry the contract:
//!
//! * **Completeness is structural, not tested.** [`Refusal::new`] is the only
//!   constructor and it takes a [`Fix`] positionally, with no default and no
//!   `Option`. A deny that declares no disposition does not compile; a deny that
//!   genuinely has no safe remedy spells [`Fix::None`], which is a statement
//!   rather than an omission. That is the difference between a contract and a
//!   convention — a test can only catch the deny sites someone remembered.
//! * **The payload is `{rule, reason, fix}`, and `fix` is never dropped.** The
//!   serialization carries `"fix": null` for [`Fix::None`] rather than skipping
//!   the key, because a consumer cannot tell an omitted field from a field the
//!   producer forgot. Byte-stable by construction (house-style §6): field order
//!   is struct order, and no value here reads a clock, a path, or an ordering.
//! * **Pointer-only** (non-negotiable rule 4). A refusal names a rule id, an
//!   operand the caller already typed, and a command to run — never file content,
//!   and never the mediated command text, which is the caller's own and could
//!   carry anything.
//!
//! **Bound (CLOUD-211, recorded on CLOUD-122):** a mediated deny originates only
//! from a computable predicate, never a judge verdict — any model signal is
//! advisory-only and structurally unable to block (house-style §0.3). So this
//! shape deliberately does **not** model advisory output: there is no confidence,
//! no severity and no "maybe", and nothing under [`crate::judge`] constructs one.
//!
//! **Why a leaf module rather than a field of the hook policy table**, which is
//! where the issue's Ready block put it: [`crate::hook`] already imports
//! [`crate::rules`], and `rules::run_static` is a deny site too. Housing the type
//! in `hook` would make `rules` import `hook` and close a module cycle for no
//! gain. The load-bearing half of that clause — *one* authoritative shape in
//! `crates/batten`, constructed at every deny site, never re-typed per harness —
//! is what this module is.

use serde::{Serialize, Serializer};

/// What to run instead — the half of a refusal that makes it actionable.
///
/// Two variants and no third: either a sanctioned alternative is declared, or it
/// is declared absent. "Not stated" is deliberately unrepresentable, which is the
/// whole mechanism (see the module doc).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fix {
    /// The sanctioned alternative for the refused intent — the exact command to
    /// run, or the surface that owns the change.
    Run(String),
    /// No safe remedy is declared for this refusal.
    ///
    /// Spelled at the deny site rather than inferred from an absent field, so the
    /// gap is a decision someone made and a reader can see. It renders as an
    /// explicit "none declared" plus the caller's general recourse, and
    /// serializes as JSON `null`.
    None,
}

impl Fix {
    /// A declared alternative, or [`Fix::None`] when the config states none.
    ///
    /// The adapter for the several config columns that are `Option<String>`
    /// today (a verb's `redirect`, a rule's stated remedy). Written once here so
    /// no deny site re-derives "absent means none".
    #[must_use]
    pub fn declared(alternative: Option<&str>) -> Fix {
        match alternative {
            Some(text) if !text.trim().is_empty() => Fix::Run(text.trim().to_owned()),
            _ => Fix::None,
        }
    }

    /// The declared alternative, if there is one.
    #[must_use]
    pub fn declared_alternative(&self) -> Option<&str> {
        match self {
            Fix::Run(text) => Some(text),
            Fix::None => None,
        }
    }
}

/// `Fix::Run` is a string and `Fix::None` is `null` — never an absent key.
///
/// Hand-written rather than derived because serde's enum representations all
/// encode the *variant*, and a consumer of `{rule, reason, fix}` wants the fix or
/// an explicit nothing, not a tag it has to unwrap.
impl Serialize for Fix {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Fix::Run(text) => serializer.serialize_str(text),
            Fix::None => serializer.serialize_none(),
        }
    }
}

/// The refusal every deny site constructs: what refused, why, and what to run.
///
/// Fields are private so [`Refusal::new`] is the only way to make one — that is
/// what makes the fix disposition mandatory rather than merely conventional.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Refusal {
    /// The id that refused: a `[[rule]]` row's id, or a derived gate's declared
    /// constant. What a reviewer greps for in `batten.toml`.
    rule: String,
    /// The declared class this refusal belongs to, when it has one (CLOUD-1050).
    ///
    /// `Some` for every one of Batten's OWN refusal sites, which name a
    /// [`crate::verdict::Native`] variant and so cannot raise a class nobody
    /// declared — the coupling is the type system's rather than a convention's.
    /// `None` for a refusal composed from a consumer's `[[rule]]` row, whose
    /// remedy is the consumer's declared `reason` under house style §8 and which
    /// is deliberately not a Batten class.
    ///
    /// Serialized as an explicit `null` rather than dropped, the same reason
    /// `fix` is: a consumer cannot tell an omitted key from an absent value.
    verdict: Option<String>,
    /// One line of why, pointer-only.
    reason: String,
    /// What to run instead, or an explicit none.
    fix: Fix,
    /// The canonical subject an admission binds to, when this refusal names one.
    ///
    /// The FIRST path-bearing subject, which is already the finding's own pointer
    /// by `.claude/rules/policy-modules.md`'s rule — so this is the same choice
    /// that surface makes, not a second one.
    ///
    /// **Carried rather than re-derived at the boundary**, and that is the whole
    /// reason the field exists. [`crate::admission::admitted`] binds five fields,
    /// one of which is the subject; a boundary that recomputed "which path was
    /// refused" from the envelope would be a second authority over a question the
    /// deny site already answered, and the two can disagree on exactly the
    /// normalization cases that made CLOUD-1133 a defect.
    ///
    /// **Not serialized**, so `-J` output is byte-identical to before (house style
    /// §6). It is an internal binding rather than news: the same pointer is
    /// already in `reason`, and a consumer gains nothing from a second copy under
    /// its own key.
    #[serde(skip_serializing)]
    subject: Option<String>,
}

/// What [`Fix::None`] renders as: the gap, stated, plus the general recourse.
///
/// A refusal with no declared alternative still owes the caller *something* — the
/// contract is that a block gets an agent to right in one hop — so the crate's own
/// general answer stands in. It is deliberately generic: which surface owns a
/// given path is the consumer's knowledge, and CLOUD-280 is where a path class
/// gets to declare it.
const NO_DECLARED_FIX: &str =
    "none declared — change it through the surface that owns it, or restore it with git";

impl Refusal {
    /// Build a refusal. The [`Fix`] is required, which is the contract.
    pub fn new(rule: impl Into<String>, reason: impl Into<String>, fix: Fix) -> Refusal {
        Refusal {
            rule: rule.into(),
            verdict: None,
            reason: reason.into(),
            fix,
            // A consumer-composed refusal carries no declared class, so there is
            // no token an admission could bind (`rules.rs`'s own words) — and a
            // subject with nothing to bind it to would read as admissible.
            subject: None,
        }
    }

    /// Build one of Batten's OWN refusals, from a declared class (CLOUD-1050).
    ///
    /// The caller names a [`crate::verdict::Native`] variant and the pointers it
    /// can offer; the gloss and the remedy come off the vendored registry, so
    /// neither is a string this call site chose. That is what makes CLOUD-122's
    /// contract structural on the native path: [`crate::verdict::validate`]
    /// refuses a class with no route and refuses one whose only route is an
    /// override, so a site physically cannot construct a refusal with no way out.
    ///
    /// `fix` is still a parameter rather than derived outright, because two of
    /// these sites can offer something narrower than the class's own route — the
    /// consumer's declared `redirect` for a protected path, for one — and a
    /// three-tier fallback that could only ever make a refusal MORE specific is
    /// worth keeping. Passing [`Fix::None`] takes the declared route.
    #[must_use]
    pub fn declared(
        rule: impl Into<String>,
        native: crate::verdict::Native,
        subjects: &[crate::verdict::Subject],
        fix: Fix,
    ) -> Refusal {
        let registry = crate::verdict::vendored();
        let token = native.id();
        let fix = match fix {
            Fix::Run(text) => Fix::Run(text),
            Fix::None => Fix::declared(crate::verdict::first_command_route(&registry, token)),
        };
        Refusal {
            rule: rule.into(),
            verdict: Some(token.to_owned()),
            reason: crate::verdict::render_line(&registry, token, subjects),
            fix,
            subject: subjects.iter().find_map(|subject| match subject {
                crate::verdict::Subject::Path { path }
                | crate::verdict::Subject::Line { path, .. } => Some(path.clone()),
                // A count or an artifact is not a path, so an admission bound to
                // it would name something the store cannot compare against the
                // tree. Skipping rather than rendering keeps "no subject" honest.
                crate::verdict::Subject::Count { .. }
                | crate::verdict::Subject::Artifact { .. } => None,
            }),
        }
    }

    /// The canonical subject an admission binds to, when this refusal names one.
    #[must_use]
    pub fn subject(&self) -> Option<&str> {
        self.subject.as_deref()
    }

    /// The declared class, or `None` for a refusal composed from consumer prose.
    #[must_use]
    pub fn verdict(&self) -> Option<&str> {
        self.verdict.as_deref()
    }

    /// The id that refused.
    #[must_use]
    pub fn rule(&self) -> &str {
        &self.rule
    }

    /// Why it refused.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    /// The fix disposition.
    #[must_use]
    pub fn fix(&self) -> &Fix {
        &self.fix
    }

    /// The text projection every channel carries.
    ///
    /// `Refused by <rule>: <reason> Fix: <fix>.` — one sentence of cause and one
    /// of remedy, in that order, with the remedy clause **always present**. A
    /// channel may append its own trailing note (the mediation hatch is
    /// [`crate::hook`]'s, not a refusal's), but nothing may drop the fix clause,
    /// because dropping it is exactly the bare "no" this contract exists to
    /// prevent.
    #[must_use]
    pub fn render(&self) -> String {
        let fix = match &self.fix {
            Fix::Run(text) => text.as_str(),
            Fix::None => NO_DECLARED_FIX,
        };
        format!(
            "Refused by {}: {} Fix: {}",
            self.rule,
            sentence(&self.reason),
            sentence(fix)
        )
    }

    /// The machine-readable payload: `{rule, reason, fix}`, byte-stable.
    ///
    /// `hook` has no `-J` channel by design — its stdout is already a
    /// harness-shaped decision document, and a second JSON shape on the same
    /// stream would break the decision channel CLOUD-40 pinned — so this is the
    /// shape a data-emitting surface projects, and what pins the serialization in
    /// tests today.
    ///
    /// # Errors
    ///
    /// Serialization of this fixed shape cannot practically fail; the `Result` is
    /// the honest signature for a serde boundary.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }
}

/// One clause, terminated exactly once.
///
/// A config author writes a paragraph ending in a period and the crate writes a
/// bare command; both are spliced into the same sentence slot, so the terminator
/// is normalised here rather than at each call site. Keeps the rendering a pure
/// function of its inputs, which is what §6 byte-stability needs.
fn sentence(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.ends_with(['.', '!', '?']) {
        trimmed.to_owned()
    } else {
        format!("{trimmed}.")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn the_payload_carries_an_explicit_null_rather_than_dropping_the_key() {
        // The acceptance's load-bearing half: a consumer cannot tell an omitted
        // field from one the producer forgot, so "no safe remedy" is a value.
        let refusal = Refusal::new("some-gate", "it fired", Fix::None);
        assert_eq!(
            refusal.to_json().expect("the fixed shape serializes"),
            r#"{"rule":"some-gate","verdict":null,"reason":"it fired","fix":null}"#
        );
    }

    #[test]
    fn a_refusal_from_consumer_prose_declares_no_class() {
        // The direction that keeps the key honest (CLOUD-1050). A refusal
        // composed from a `[[rule]]` row's own `reason` is the CONSUMER's
        // statement, and labelling it with a Batten class would make the two
        // indistinguishable to any reader keying on the token — which is the
        // whole reason the token exists.
        assert_eq!(
            Refusal::new("some-gate", "it fired", Fix::None).verdict(),
            None
        );
    }

    #[test]
    fn a_native_refusal_carries_its_declared_class_and_that_classs_remedy() {
        // The other direction, and the structural half of CLOUD-122. Nothing at
        // the call site chose either the gloss or the fix: passing `Fix::None`
        // takes the class's first `command` route, and `verdict::validate`
        // refuses a class that declares none reachable — so a native site cannot
        // construct a refusal with no way out even by omission.
        let refusal = Refusal::declared(
            "provision",
            crate::verdict::Native::ScannerUnprovisioned,
            &[crate::verdict::Subject::Artifact {
                artifact: "gitleaks".to_owned(),
            }],
            Fix::None,
        );
        assert_eq!(refusal.verdict(), Some("V-SCANNER-UNPROVISIONED"));
        assert!(
            refusal.reason().starts_with("V-SCANNER-UNPROVISIONED ("),
            "the hot path leads with the token: {}",
            refusal.reason()
        );
        assert!(
            refusal.reason().ends_with(" gitleaks"),
            "and carries the pointer inline rather than behind `explain`: {}",
            refusal.reason()
        );
        assert_eq!(
            refusal.fix(),
            &Fix::Run("batten provision".to_owned()),
            "the remedy came off the declared route, not off this call site"
        );
    }

    #[test]
    fn a_narrower_fix_at_the_site_still_wins_over_the_declared_route() {
        // The protected-path tier (CLOUD-280): a consumer's own `[[redirect]]`
        // is more specific than the class's general route, so the class is a
        // FLOOR rather than a ceiling. Without this the migration would have
        // silently flattened three tiers into one.
        let refusal = Refusal::declared(
            "protected-mutation",
            crate::verdict::Native::ProtectedMutation,
            &[],
            Fix::Run("use `serena rename_memory`".to_owned()),
        );
        assert_eq!(
            refusal.fix(),
            &Fix::Run("use `serena rename_memory`".to_owned())
        );
    }

    #[test]
    fn a_declared_fix_is_the_bare_string_never_a_tagged_variant() {
        let refusal = Refusal::new("some-gate", "it fired", Fix::Run("run this".to_owned()));
        assert_eq!(
            refusal.to_json().expect("the fixed shape serializes"),
            r#"{"rule":"some-gate","verdict":null,"reason":"it fired","fix":"run this"}"#
        );
    }

    #[test]
    fn the_payload_is_byte_stable() {
        // §6: same input, same bytes. Nothing here reads a clock or a path, so
        // this is a property of the type rather than of the caller.
        let refusal = Refusal::new("some-gate", "it fired", Fix::Run("run this".to_owned()));
        assert_eq!(refusal.to_json().unwrap(), refusal.to_json().unwrap());
    }

    #[test]
    fn the_rendering_always_carries_a_fix_clause() {
        // Both dispositions, because the one that matters is the one with nothing
        // declared: that is where a bare "no" would come from.
        assert!(
            Refusal::new("g", "why", Fix::None)
                .render()
                .contains("Fix: none declared")
        );
        assert!(
            Refusal::new("g", "why", Fix::Run("do this".to_owned()))
                .render()
                .contains("Fix: do this.")
        );
    }

    #[test]
    fn a_clause_is_terminated_exactly_once() {
        // A config author's paragraph already ends in a period; a bare command
        // does not. Both land in the same slot, so the terminator is normalised
        // rather than doubled.
        let authored = Refusal::new("g", "Because it does.", Fix::Run("mise run x".to_owned()));
        assert_eq!(
            authored.render(),
            "Refused by g: Because it does. Fix: mise run x."
        );
        let bare = Refusal::new("g", "because it does", Fix::Run("mise run x.".to_owned()));
        assert_eq!(
            bare.render(),
            "Refused by g: because it does. Fix: mise run x."
        );
    }

    #[test]
    fn an_absent_or_blank_declaration_is_none_never_an_empty_fix() {
        // `declared` is the one adapter from the config columns that are
        // `Option<String>`. A whitespace-only value is a declaration nobody made,
        // and rendering it would produce `Fix: .` — a fix clause that is present
        // and says nothing, which is worse than the explicit none.
        assert_eq!(Fix::declared(None), Fix::None);
        assert_eq!(Fix::declared(Some("   ")), Fix::None);
        assert_eq!(Fix::declared(Some(" x ")), Fix::Run("x".to_owned()));
    }
}
