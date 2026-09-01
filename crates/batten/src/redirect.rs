//! The per-path-class redirect table (CLOUD-280): what to run instead, keyed by
//! **what is protected** rather than by the verb reaching for it.
//!
//! CLOUD-96 shipped the sanctioned mutation on the `[[verb]]` row, because a
//! per-class one was not expressible then. That gets the refusal contract
//! (CLOUD-122) mostly right — `rm` has one obvious alternative most of the time
//! — but the *useful* remedy is a property of the target: `rm` against agent
//! memory should name the memory-write surface, `rm` against a committed
//! workflow should say to delete it in a PR, `rm` against generated output
//! should say to re-run the generator. One string on the verb has to be vague
//! enough to cover all three, and a vague fix is the un-actionable refusal the
//! contract exists to prevent.
//!
//! The duplication that forced this was measured rather than predicted. Once
//! CLOUD-312 made the write *tools* verbs and CLOUD-442 added the qualifier
//! columns, this repository's own table reached seventeen `redirect` strings of
//! which **ten** carried the same per-path clause verbatim — one fact about
//! `.serena/memories/**`, copy-pasted across every program that can reach it,
//! because there was nowhere else to put it.
//!
//! Load-bearing choices:
//!
//! * **A sibling table, not a wider `protected`.** The direct approach —
//!   widening `protected` to `{glob, mutation}` — breaks
//!   [`crate::trust::weakenings`], whose `protected[<entry>]` keys are how the
//!   raise-only comparison names a removed guard. Those keys stay byte-identical
//!   because `protected` keeps its element type; this table only says what to
//!   *suggest*, so the two can never disagree about coverage.
//! * **Declaration order decides, first match wins.** The same tie-break
//!   [`crate::hook`]'s shape rows use, and for the reason stated there: a
//!   reviewer reads a table top to bottom, and any cleverer precedence is a rule
//!   about rules that the config does not state. "Most specific glob" has no
//!   cheap definition and would be one.
//! * **A redirect is not policy-bearing.** It changes what a refusal *says*,
//!   never whether the refusal fires, so §8's raise-only clamp does not apply to
//!   it — stated here rather than left to inference. What the local layer still
//!   may not do is *redefine* a committed row, which is coherence with every
//!   other table rather than a weakening this one could express.
//! * **It makes a message specific; it does not make a surface reachable.**
//!   CLOUD-663 was canceled on exactly this distinction: a redirect naming a
//!   surface that is down is a defect in the surface, not in the redirect, and
//!   a second sanctioned writer would have hidden it permanently.
//!
//! The glob matcher is [`crate::rules::glob_match`] — one glob semantics for the
//! whole engine, never a second implementation.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::UsageError;
use crate::rules::glob_match;

/// One declared path class and the mutation sanctioned for it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Redirect {
    /// The path class this redirect speaks for, in the engine's one glob
    /// dialect.
    ///
    /// Deliberately independent of `protected`: this table answers "what should
    /// they run instead", never "is this guarded". A glob here matching a path
    /// no `protected` entry covers simply never comes up, which is the harmless
    /// direction — the alternative, deriving protection from a redirect, is the
    /// set-collapsing CLOUD-37 exists to prevent.
    pub glob: String,
    /// The sanctioned mutation for that class — the "run this instead" a deny
    /// carries.
    pub mutation: String,
    /// The sanctioned READ for that class, and the whole of the read-side gate
    /// (CLOUD-1258).
    ///
    /// # Why a read is gated at all
    ///
    /// `no-tool-substitution` is `kind = "pipeline"` and decides over shell
    /// argv, so a structured-tool call is invisible to it; `protected` crossed
    /// with `[[verb]]` enumerates MUTATIONS, and CLOUD-442's port states "reads
    /// stay allowed". So a generic file read of a memory was gated by nothing,
    /// measured 2026-08-31 with the Serena server healthy and `read_memory`
    /// loadable. That is not a style preference: a path read couples the caller
    /// to the tree layout, and CLOUD-868 proposes moving that tree — `read_memory`
    /// survives the move and a hardcoded path does not, so every flat-path read
    /// is an unmigrated call site against it.
    ///
    /// # OPTIONAL, AND THE ABSENCE IS THE "SESSION DOES NOT OFFER IT" ARM
    ///
    /// The row demands that the gate allow where the tool is not available,
    /// because a redirect naming a tool the session does not carry is CLOUD-998's
    /// defect one layer over. The boundary cannot see whether an MCP server is
    /// healthy — that is not a fact any mediated payload carries — so the
    /// question is answered where it IS decidable: the consumer declares the
    /// read remedy, and a consumer without the tool declares none and is refused
    /// nothing. The remedy is therefore a string its own author wrote, which is
    /// the strongest available guarantee that it names something reachable.
    ///
    /// A row with no `read` key gates nothing on the read side and keeps its
    /// mutation half exactly as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read: Option<String>,
}

/// Reject a table that would make a refusal dishonest or silent.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for an empty `glob`, an empty
/// `mutation`, or a duplicated `glob`. The last is the load-bearing one: two
/// rows for one path class are two answers to one question, and silently taking
/// the first is how a corrected remedy gets lost behind a stale row — the same
/// refusal [`crate::verbs::validate`] gives a verb declared twice.
///
/// An empty `mutation` is refused rather than treated as absent, because it
/// would render a fix clause that is present and says nothing, which reads worse
/// than the explicit "none declared" a row's absence already produces.
pub fn validate(table: &[Redirect]) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        if entry.glob.trim().is_empty() {
            return Err(UsageError::raise(
                "redirect: `glob` must not be empty".to_owned(),
            ));
        }
        if entry.mutation.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "redirect {}: `mutation` must not be empty — a redirect that names nothing is a \
                 fix clause that says nothing",
                entry.glob
            )));
        }
        // Same refusal as `mutation`'s, for the same reason: a declared `read`
        // that says nothing renders a fix clause that says nothing, which reads
        // worse than the row simply not declaring one. Absent and empty are
        // different statements and the engine keeps them different.
        if entry
            .read
            .as_ref()
            .is_some_and(|read| read.trim().is_empty())
        {
            return Err(UsageError::raise(format!(
                "redirect {}: `read` is declared and empty — omit the key to gate no read, or \
                 name the tool that answers",
                entry.glob
            )));
        }
        if table[..index].iter().any(|prior| prior.glob == entry.glob) {
            return Err(UsageError::raise(format!(
                "redirect {}: declared twice; a path class has one sanctioned mutation",
                entry.glob
            )));
        }
    }
    Ok(())
}

/// The mutation declared for `path`, if any row claims it.
///
/// First match in declaration order — see the module doc for why that is the
/// tie-break and not "most specific". `None` means no row speaks for this path,
/// which leaves the caller to fall back to the verb's own redirect.
#[must_use]
pub fn resolve<'table>(table: &'table [Redirect], path: &str) -> Option<&'table str> {
    table
        .iter()
        .find(|entry| glob_match(&entry.glob, path))
        .map(|entry| entry.mutation.as_str())
}

/// The sanctioned READ declared for `path`, if any row declares one
/// (CLOUD-1258).
///
/// Same table, same first-match-in-declaration-order tie-break. `None` is the
/// whole read-side allow arm: no row speaks for this path, or the row that does
/// declares no read remedy — and the second is how a consumer without the tool
/// says so.
///
/// **The first matching row decides, and a later row's `read` does not rescue
/// it.** That is deliberate rather than incidental: `resolve` already reads the
/// table that way for mutations, and a `read` lookup with a different precedence
/// would make one table answer two questions in two orders.
#[must_use]
pub fn resolve_read<'table>(table: &'table [Redirect], path: &str) -> Option<&'table str> {
    table
        .iter()
        .find(|entry| glob_match(&entry.glob, path))
        .and_then(|entry| entry.read.as_deref())
}

/// The words of the `batten` invocation a remedy names, or `None` for a remedy
/// that names none (CLOUD-1189).
///
/// # An invocation is a CODE SPAN, and that bound is the whole of what makes
/// this decidable
///
/// A remedy is a sentence, and a sentence does not say where its command stops.
/// The first version of this collected every following token that LOOKED like a
/// subcommand word, which reads `run `batten capture show <handle>` instead` as
/// a four-word invocation ending in `instead` — and then reports `instead` as an
/// undeclared rule id. That is a finding invented out of English, and it is the
/// false positive that gets a gate switched off.
///
/// A backtick-delimited span has an author-written end, so inside it every word
/// IS part of the command and the rule-id arm below can be exact rather than a
/// guess. `verify` over this repository's own table is what the bound is sized
/// against.
///
/// **What it deliberately under-denies, stated rather than discovered:** a
/// remedy naming a command in bare prose. That is the sanctioned direction here
/// — the alternative is not a stricter gate but a wrong one, and this repository
/// writes every remedy's command as a code span.
fn invocation(text: &str) -> Option<Vec<String>> {
    for span in text.split('`').skip(1).step_by(2) {
        let mut words = span.split_whitespace();
        if words.next() != Some("batten") {
            continue;
        }
        let taken: Vec<String> = words.map(str::to_owned).collect();
        if !taken.is_empty() {
            return Some(taken);
        }
    }
    None
}

/// `--json` — a flag, judged by neither authority.
///
/// Which flags a verb takes is `SURFACE`'s own declaration and `clap`'s to
/// enforce at the call; resolving one here would be a third reading of it.
fn is_flag(word: &str) -> bool {
    word.starts_with('-')
}

/// `<handle>` — an operand the author wrote as a hole to fill in.
///
/// Judged by neither authority: what a verb's operands may be is a per-verb
/// arity question, and this row reads the command surface and the rule table
/// rather than a third one.
fn is_placeholder(word: &str) -> bool {
    word.starts_with('<') && word.ends_with('>') && word.len() > 2
}

/// Refuse a remedy naming a `batten` command that resolves to nothing
/// (CLOUD-1189).
///
/// # Why this exists
///
/// A deny naming a command that does not exist is worse than a deny naming
/// none: it sends the reader to a shell error instead of a remedy, and it looks
/// authoritative doing it. `redirect` strings are free-form prose and nothing
/// resolved the command they name against anything, so a renamed verb turned
/// every remedy naming it into a lie, silently.
///
/// # Both object shapes, because a gate that knew one would report the other
///
/// `batten show config` resolves against [`crate::surface::SURFACE`];
/// `batten check <rule-id>` resolves its prefix against `SURFACE` and its
/// remaining word against the declared `[[rule]]` table. A checker knowing only
/// the first would report every rule-scoped remedy as broken, which is the false
/// positive that gets a gate switched off.
///
/// # What it deliberately does not decide
///
/// A remedy naming a **non-batten** command (`mise run …`, `git …`) — that is
/// the operator's PATH, and resolving it needs a second authority over what is
/// installed, which is `policy/verdict-routes-resolve.rego`'s `mise run` arm and
/// not this one. Whether the remedy is *good* advice, which is judgement and
/// rule 3 forbids gating it. And an operand written as a `<placeholder>`.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) naming the remedy's own key and the
/// unresolvable words. **Pointer-only** (rule 4): the key and the command, never
/// the remedy prose that carries it.
pub fn validate_remedies<'a>(
    remedies: impl IntoIterator<Item = (String, &'a str)>,
    rules: &[String],
) -> Result<()> {
    for (key, text) in remedies {
        let Some(words) = invocation(text) else {
            continue;
        };
        let mut matched = 0;
        for take in (1..=words.len()).rev() {
            let candidate = words[..take].join(" ");
            if crate::surface::SURFACE
                .iter()
                .any(|decl| decl.path == candidate)
            {
                matched = take;
                break;
            }
        }
        if matched == 0 {
            return Err(UsageError::raise(format!(
                "{key}: the remedy names `batten {}`, which is not a declared command — correct \
                 the remedy, or declare the command on the surface",
                words.join(" ")
            )));
        }
        for word in &words[matched..] {
            if is_flag(word) || is_placeholder(word) || rules.iter().any(|id| id == word) {
                continue;
            }
            return Err(UsageError::raise(format!(
                "{key}: the remedy names `batten {}` and then `{word}`, which is neither a \
                 declared rule id nor a <placeholder> — correct the remedy, or declare the rule",
                words[..matched].join(" ")
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(glob: &str, mutation: &str) -> Redirect {
        Redirect {
            glob: glob.to_owned(),
            mutation: mutation.to_owned(),
            read: None,
        }
    }

    #[test]
    fn a_declared_class_resolves_to_its_mutation() {
        let table = [row("guarded/**", "use the surface that owns it")];
        assert_eq!(
            resolve(&table, "guarded/thing.md"),
            Some("use the surface that owns it")
        );
    }

    #[test]
    fn a_path_no_row_claims_resolves_to_nothing() {
        // Not an error and not a default: "no row speaks for this path" is what
        // lets the caller fall back to the verb's own redirect, which is the
        // tier CLOUD-96 shipped and this table sits in front of.
        let table = [row("guarded/**", "use the surface that owns it")];
        assert_eq!(resolve(&table, "elsewhere/thing.md"), None);
        assert_eq!(resolve(&[], "guarded/thing.md"), None);
    }

    #[test]
    fn the_first_matching_row_wins_in_declaration_order() {
        // The tie-break, as a test rather than a comment. Both globs match, and
        // the narrower one is declared FIRST — which is the whole point: the
        // config author orders the table, the engine does not rank it.
        let table = [
            row("guarded/secrets/**", "rotate it, do not edit it"),
            row("guarded/**", "use the surface that owns it"),
        ];
        assert_eq!(
            resolve(&table, "guarded/secrets/key.md"),
            Some("rotate it, do not edit it")
        );
        // And the later row still answers for everything the earlier one misses,
        // so ordering narrow-first is a usable discipline rather than a trap.
        assert_eq!(
            resolve(&table, "guarded/notes.md"),
            Some("use the surface that owns it")
        );
    }

    #[test]
    fn a_class_declared_twice_is_a_usage_error() {
        // Two answers to one question. Taking the first silently is how a
        // corrected remedy gets lost behind a stale row.
        let table = [row("guarded/**", "first"), row("guarded/**", "second")];
        let err = validate(&table).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn an_empty_glob_or_mutation_is_a_usage_error() {
        assert!(validate(&[row("", "something")]).is_err());
        assert!(validate(&[row("guarded/**", "")]).is_err());
        // Whitespace is not a declaration either — it would render `Fix: .`
        assert!(validate(&[row("guarded/**", "   ")]).is_err());
        assert!(validate(&[row("guarded/**", "something")]).is_ok());
    }

    #[test]
    fn two_distinct_classes_coexist() {
        let table = [row("a/**", "first"), row("b/**", "second")];
        assert!(validate(&table).is_ok());
        assert_eq!(resolve(&table, "b/x"), Some("second"));
    }

    #[test]
    fn the_source_bakes_in_no_path_class() {
        // Non-negotiable rule 1, in the `verbs::the_source_bakes_in_no_verb`
        // idiom: which paths a repository protects, and what it wants run
        // instead, are the consumer's policy. Asserted behaviourally — the same
        // path must get opposite answers from two tables differing only in their
        // rows, which a hardcoded class could not produce.
        let declaring = [row("guarded/**", "the declared remedy")];
        let elsewhere = [row("other/**", "the declared remedy")];
        assert_eq!(
            resolve(&declaring, "guarded/thing"),
            Some("the declared remedy")
        );
        assert_eq!(resolve(&elsewhere, "guarded/thing"), None);
    }
}
