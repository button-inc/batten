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
//! The glob matcher is [`crate::selector::glob_match`] — one glob semantics for the
//! whole engine, never a second implementation.

use crate::config_model::Redirect;
use batten_core::selector::glob_match;

/// The table with every `read` dropped whose `read_server` `resolves` says no
/// source can reach (CLOUD-2229): a refusal must name a route that can be taken.
#[must_use]
pub fn offered(table: &[Redirect], resolves: impl Fn(&str) -> bool) -> Vec<Redirect> {
    table
        .iter()
        .cloned()
        .map(|mut row| {
            if row
                .read_server
                .as_deref()
                .is_some_and(|server| !resolves(server))
            {
                row.read = None;
            }
            row
        })
        .collect()
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn row(glob: &str, mutation: &str) -> Redirect {
        Redirect {
            glob: glob.to_owned(),
            mutation: mutation.to_owned(),
            read: None,
            read_server: None,
        }
    }

    #[test]
    fn a_memory_read_is_admitted_where_no_source_resolves_its_server() {
        // CLOUD-2229. Measured on #1132: no declared source resolved `serena` in
        // a cloud session, so `read_memory` was a route nobody could take.
        let memory = Redirect {
            read: Some("read_memory".to_owned()),
            read_server: Some("serena".to_owned()),
            ..row(".serena/memories/**", "use Serena's memory tools")
        };
        let unreachable = offered(std::slice::from_ref(&memory), |_| false);
        assert_eq!(resolve_read(&unreachable, ".serena/memories/core.md"), None);
        let reachable = offered(std::slice::from_ref(&memory), |server| server == "serena");
        assert_eq!(
            resolve_read(&reachable, ".serena/memories/core.md"),
            Some("read_memory")
        );
        // A row naming no server refuses as it always did.
        let unnamed = Redirect {
            read_server: None,
            ..memory
        };
        let kept = offered(std::slice::from_ref(&unnamed), |_| false);
        assert_eq!(
            resolve_read(&kept, ".serena/memories/core.md"),
            Some("read_memory")
        );
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
    fn two_distinct_classes_coexist() {
        let table = [row("a/**", "first"), row("b/**", "second")];
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
