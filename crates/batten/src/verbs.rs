//! The mutating-verb table (CLOUD-36): which shell programs change the world?
//!
//! A guard that wants to refuse `rm` against managed state needs two things it
//! cannot invent — the set of paths that are protected, and the set of programs
//! that mutate. This module owns the second. It is the table and the lookup and
//! nothing else: crossing it with a path set is the gate CLOUD-96 builds on top
//! (`{verb ∈ this table} × {path ∈ protected}`), and the path sets themselves
//! are CLOUD-37's. Keeping the three apart is what lets each have one authority.
//!
//! Load-bearing choices:
//!
//! * **The table is config, never crate constants** (non-negotiable rule 1).
//!   Which programs count as mutating is a property of the repository being
//!   guarded — one repo's `terraform apply` is another's irrelevance — so
//!   `crates/batten` names no verb, and a grep for one returns zero hits.
//!   Batten's own table lives in Batten's own `batten.toml`, as consumer #1.
//! * **The severity axis is [`Effect`]**, the house-style §5 vocabulary, not a
//!   second one invented here. A verb is `write` or `destructive` — the same
//!   words a command's own effect entry uses — so `-y --yes` keeps meaning one
//!   thing across the tool. §5's raise-only `max_effect` rule is **specified,
//!   not implemented**: [`Effect`] carries no ordering to take a maximum over,
//!   and the implementation rides CLOUD-27's spec work (CLOUD-217 (22)).
//!   Sharing the vocabulary now is precisely what makes that a later *addition*
//!   rather than a later reconciliation of two.
//! * **A verb carries its redirect.** The refusal contract (CLOUD-122) is that
//!   every deny names the fix, and the sanctioned mutation for a path class is
//!   knowledge the config author has and the core does not. Declaring it beside
//!   the verb is what keeps CLOUD-96's deny message out of the crate.
//! * **Lookup is exact on the program name, never a substring.** Matching
//!   loosely is how a guard denies `remove_stale_cache` because it contains
//!   `rm`; the *effective* program is what the caller passes in, and extracting
//!   it from a command line — wrapper lookthrough, env prefixes, quoted spans —
//!   is [`crate::hook`]'s parser, not a second one here.
//! * **The qualifiers narrow, never widen** (CLOUD-442). A program name alone
//!   cannot say that only a destination is written, that only an in-place flag
//!   mutates, or that only some subcommands do — so three optional columns say
//!   it, and an absent column leaves a row meaning exactly what it meant
//!   before. Each one can only make a row match *less*, which is why adding
//!   them cannot weaken a policy already declared.
//!
//!   They are still the table's business rather than the parser's: [`qualify`]
//!   decides over tokens [`crate::hook`] has **already** extracted, so this
//!   module never reads a command line and there is still one parser in the
//!   tree. [`classify`] is defined over [`qualify`] for the same reason — a
//!   second matcher is a second answer to "does this row apply", and the one
//!   place that would show up is a surface that parses no arguments, where a
//!   qualified row must never fire.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::effect::Effect;
use crate::error::UsageError;

/// Which operands of a matched invocation are write targets.
///
/// [`OperandScope::All`] is the default, and that is load-bearing rather than
/// incidental: it is the reading that fails toward *refusing*, and it is the one
/// a move needs — guarding only the source would miss the direction that
/// destroys the destination, which
/// `hook::tests::every_operand_is_a_candidate_so_a_destination_is_guarded_too`
/// pins. [`OperandScope::Last`] is the narrowing a destination-only program
/// needs, where copying a guarded file *out* of the guarded set is a read and
/// refusing it is the false positive that gets a guard switched off.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperandScope {
    /// Every operand is a candidate target.
    #[default]
    All,
    /// Only the final operand is a target — the destination.
    Last,
}

/// One mutating program declared in `batten.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MutatingVerb {
    /// The program name as it appears on a command line, e.g. the basename of
    /// the executable. Matched exactly.
    pub verb: String,
    /// What running it does, in the one effect vocabulary: `write` for state
    /// the caller can recreate, `destructive` for state whose recovery means
    /// redoing work.
    pub effect: Effect,
    /// The sanctioned mutation to point at when this verb is refused — the
    /// "run this instead" half of the refusal contract. Optional, because not
    /// every verb has an alternative; a consumer with none falls back to
    /// naming the rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect: Option<String>,
    /// The subcommand that makes this program a mutation, where the program
    /// alone is not one.
    ///
    /// A front-end dispatching on its first argument mutates under some of them
    /// and reads under the rest — the effective program is the same word either
    /// way, so a row keyed on it alone would refuse every read it also spells.
    /// One row per mutating subcommand, which is why the duplicate check keys on
    /// the pair rather than on the program.
    ///
    /// Matched against the **first** argument only, exactly as the table this
    /// ports from did: a global option written before the subcommand hides it,
    /// which under-denies — the sanctioned direction (house-style §5).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subcommand: Option<String>,
    /// The flags, any one of which turns this program into a mutation.
    ///
    /// A stream editor writes only in place; every other invocation of it is a
    /// read, so a row with no flag column would refuse the whole read half. The
    /// entries are spellings of one switch, so **any** match qualifies, and a
    /// declared flag also matches its value-bearing forms (`<flag>.<suffix>`,
    /// `<flag>=<value>`) — the way an in-place switch is written with a backup
    /// suffix.
    ///
    /// Bundled short flags are deliberately **not** decomposed: a switch hidden
    /// inside a cluster goes unseen, which under-denies, and the table this
    /// ports from did not decompose them either.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requires_flag: Option<Vec<String>>,
    /// Which of this verb's operands its mutation targets. Absent means
    /// [`OperandScope::All`], the conservative reading.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operands: Option<OperandScope>,
}

impl MutatingVerb {
    /// The operand scope this row declares, with the conservative default
    /// applied — the one place absence is resolved, so no caller may read it the
    /// widening way.
    #[must_use]
    pub fn operand_scope(&self) -> OperandScope {
        self.operands.unwrap_or_default()
    }

    /// This row's identity: the program **and** the subcommand it qualifies.
    ///
    /// Keyed on the pair rather than the program because two subcommands of one
    /// front-end are two different actions with two different remedies, and
    /// that is the whole capability the column adds. Within one pair the old
    /// invariant is untouched: one effect, one redirect.
    fn key(&self) -> (&str, Option<&str>) {
        (self.verb.as_str(), self.subcommand.as_deref())
    }

    /// Whether this row's qualifiers hold for `arguments`, and how many leading
    /// tokens they consumed.
    ///
    /// `None` is "this row does not apply to this invocation" — the narrowing
    /// the columns exist for. The count is what keeps operand scanning honest: a
    /// consumed subcommand is not an operand, and counting it as one would make
    /// the first argument look like a target.
    fn qualifies(&self, arguments: &[&str]) -> Option<usize> {
        let consumed = match self.subcommand.as_deref() {
            None => 0,
            Some(subcommand) => {
                if arguments.first().copied() != Some(subcommand) {
                    return None;
                }
                1
            }
        };
        if let Some(flags) = self.requires_flag.as_deref() {
            let rest = arguments.get(consumed..).unwrap_or_default();
            if !rest
                .iter()
                .any(|token| flags.iter().any(|flag| flag_matches(flag, token)))
            {
                return None;
            }
        }
        Some(consumed)
    }

    /// Reject an entry that would make the table dishonest.
    ///
    /// # Errors
    ///
    /// Returns a [`UsageError`] (→ exit `1`) for an empty `verb`, for a `verb`
    /// carrying whitespace (a command line, not a program), or for an `effect`
    /// that does not describe a mutation. The last is the load-bearing one: a
    /// verb declared `read` in the *mutating*-verb table would sit there
    /// matching nothing while reading as covered — a gate that is present and
    /// inert, which is worse than an absent one.
    ///
    /// The qualifier columns are refused on the same principle, in their own
    /// inert shapes: an empty `requires_flag` list, an entry in it that is not a
    /// flag, or a `subcommand` that is empty, dash-led or more than one word.
    /// Each of those is a row that loads clean and can never match, which is
    /// exactly the present-and-inert gate the effect check exists to prevent.
    fn validate(&self) -> Result<()> {
        if self.verb.is_empty() {
            return Err(UsageError::raise("verb: `verb` must not be empty"));
        }
        if self.verb.split_whitespace().count() != 1 {
            return Err(UsageError::raise(format!(
                "verb {:?}: `verb` names one program, not a command line",
                self.verb
            )));
        }
        if let Some(subcommand) = self.subcommand.as_deref() {
            if subcommand.split_whitespace().count() != 1 {
                return Err(UsageError::raise(format!(
                    "verb {}: `subcommand` names one word, not a command line",
                    self.verb
                )));
            }
            if subcommand.starts_with('-') {
                return Err(UsageError::raise(format!(
                    "verb {}: `subcommand` {subcommand:?} looks like a flag; a flag-qualified \
                     mutation is `requires_flag`",
                    self.verb
                )));
            }
        }
        if let Some(flags) = self.requires_flag.as_deref() {
            if flags.is_empty() {
                return Err(UsageError::raise(format!(
                    "verb {}: `requires_flag` is empty — a row requiring one of no flags can \
                     never match",
                    self.verb
                )));
            }
            for flag in flags {
                if !flag.starts_with('-') || flag.split_whitespace().count() != 1 {
                    return Err(UsageError::raise(format!(
                        "verb {}: `requires_flag` entry {flag:?} is not a flag; operands are not \
                         matched here",
                        self.verb
                    )));
                }
            }
        }
        if !matches!(self.effect, Effect::Write | Effect::Destructive) {
            return Err(UsageError::raise(format!(
                "verb {}: `effect` must be \"{}\" or \"{}\", got \"{}\" — a non-mutating entry in \
                 the mutating-verb table is an inert gate",
                self.verb,
                Effect::Write.as_str(),
                Effect::Destructive.as_str(),
                self.effect.as_str()
            )));
        }
        Ok(())
    }
}

/// Whether `token` is the declared `flag`, or one of its value-bearing forms.
///
/// The two suffix forms are how an in-place switch carries a backup suffix and
/// how a long flag carries a value. A bare prefix match is deliberately not
/// accepted: it would read a longer, unrelated flag as the declared one, which
/// is the substring mistake [`classify`] refuses one level up.
fn flag_matches(flag: &str, token: &str) -> bool {
    token == flag
        || token
            .strip_prefix(flag)
            .is_some_and(|rest| rest.starts_with('.') || rest.starts_with('='))
}

/// A row matched against one parsed invocation, with its qualifiers resolved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qualified<'table> {
    /// The row that matched.
    pub verb: &'table MutatingVerb,
    /// How many leading argument tokens the row's `subcommand` consumed, so a
    /// caller scans operands from past them.
    pub consumed: usize,
    /// Which of the remaining operands are targets.
    pub operands: OperandScope,
}

/// The first row, in declaration order, that applies to this invocation.
///
/// `program` and `arguments` are what [`crate::hook`]'s parser resolved — the
/// effective program and the tokens after it, flags included and quotes already
/// applied. This function reads no command line and splits no string; it decides
/// which declared row a parsed invocation satisfies.
///
/// Declaration order is the tie-break rather than "most specific wins", the same
/// choice the shape rows make: a reviewer reads the table top to bottom, and a
/// cleverer precedence would be a rule about rules the config does not state.
#[must_use]
pub fn qualify<'table>(
    table: &'table [MutatingVerb],
    program: &str,
    arguments: &[&str],
) -> Option<Qualified<'table>> {
    table.iter().find_map(|entry| {
        if entry.verb != program {
            return None;
        }
        Some(Qualified {
            verb: entry,
            consumed: entry.qualifies(arguments)?,
            operands: entry.operand_scope(),
        })
    })
}

/// Validate a whole table, and refuse a duplicate declaration.
///
/// Two rows for one verb *and subcommand* is a policy question with two answers
/// — which effect, which redirect — and silently taking the first is how a
/// tightening edit gets lost behind a stale row. Two rows differing in their
/// subcommand are not that: they are two actions, which is the whole point of
/// the column.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a malformed or duplicated entry.
pub fn validate(table: &[MutatingVerb]) -> Result<()> {
    for (index, entry) in table.iter().enumerate() {
        entry.validate()?;
        if table[..index]
            .iter()
            .any(|prior| prior.key() == entry.key())
        {
            return Err(UsageError::raise(format!(
                "verb {}: declared twice; a verb has one effect and one redirect",
                entry.verb
            )));
        }
    }
    Ok(())
}

/// Look `program` up in the table.
///
/// `None` means "not declared mutating", which for this primitive is simply an
/// absence of information — the conservative reading of an unknown program
/// belongs to the consumer's own policy (house-style §5: absence means *ask*,
/// never *safe*), not to a lookup.
///
/// Exact match, deliberately: `program` is the effective program a caller has
/// already extracted, and substring matching is how a guard refuses
/// `rmdir_helper` for containing a shorter verb.
///
/// Defined as [`qualify`] over **no arguments**, which is the honest reading of
/// a lookup by program alone: a row whose mutation is qualified by a flag or a
/// subcommand has nothing here to satisfy it, so it does not match. That is what
/// keeps a surface carrying no argv — a write tool naming one path — from firing
/// a row that was declared about a command line (CLOUD-442).
#[must_use]
pub fn classify<'table>(
    table: &'table [MutatingVerb],
    program: &str,
) -> Option<&'table MutatingVerb> {
    qualify(table, program, &[]).map(|matched| matched.verb)
}

/// Every verb in the table declaring exactly `effect`, in declaration order.
///
/// Derived from the effect each verb declares rather than from a second
/// hand-kept list — the same posture that makes the read-only allowlist a
/// `filter` over the effect table (house-style §5).
#[must_use]
pub fn with_effect(table: &[MutatingVerb], effect: Effect) -> Vec<&MutatingVerb> {
    table
        .iter()
        .filter(|entry| entry.effect == effect)
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn verb(name: &str, effect: Effect) -> MutatingVerb {
        MutatingVerb {
            verb: name.to_owned(),
            effect,
            redirect: None,
            subcommand: None,
            requires_flag: None,
            operands: None,
        }
    }

    /// The same row with a subcommand qualifier.
    fn under(name: &str, subcommand: &str) -> MutatingVerb {
        MutatingVerb {
            subcommand: Some(subcommand.to_owned()),
            ..verb(name, Effect::Destructive)
        }
    }

    /// The same row with a flag qualifier.
    fn behind(name: &str, flags: &[&str]) -> MutatingVerb {
        MutatingVerb {
            requires_flag: Some(flags.iter().map(|flag| (*flag).to_owned()).collect()),
            ..verb(name, Effect::Write)
        }
    }

    #[test]
    fn a_non_mutating_entry_is_refused_rather_than_kept_inert() {
        // A `read` row in the mutating-verb table would match nothing while
        // reading as covered — present and inert, which is worse than absent.
        for effect in [Effect::Read, Effect::Unclassified, Effect::Ask] {
            let err = verb("x", effect).validate().unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "{} is not a mutation",
                effect.as_str()
            );
        }
        assert!(verb("x", Effect::Write).validate().is_ok());
        assert!(verb("x", Effect::Destructive).validate().is_ok());
    }

    #[test]
    fn a_verb_names_one_program_not_a_command_line() {
        assert!(verb("", Effect::Write).validate().is_err());
        assert!(verb("a b", Effect::Write).validate().is_err());
    }

    #[test]
    fn a_verb_declared_twice_is_a_usage_error() {
        let table = [verb("x", Effect::Write), verb("x", Effect::Destructive)];
        let err = validate(&table).unwrap_err();
        assert!(err.downcast_ref::<UsageError>().is_some());
    }

    #[test]
    fn lookup_is_exact_never_a_substring() {
        let table = [verb("x", Effect::Destructive)];
        assert!(classify(&table, "x").is_some());
        // The bug this pins: a guard that refuses a longer program for
        // containing a shorter verb.
        assert!(classify(&table, "xy").is_none());
        assert!(classify(&table, "yx").is_none());
        assert!(classify(&table, "").is_none());
    }

    #[test]
    fn an_unqualified_row_matches_whatever_the_arguments_are() {
        // The default is untouched by CLOUD-442: a row with no qualifier means
        // what it always meant, so adding the columns cannot weaken a policy
        // already declared.
        let table = [verb("p", Effect::Destructive)];
        for arguments in [&[][..], &["x"], &["-f", "x"], &["sub", "x"]] {
            let matched = qualify(&table, "p", arguments).expect("an unqualified row applies");
            assert_eq!(matched.consumed, 0);
            assert_eq!(matched.operands, OperandScope::All);
        }
    }

    #[test]
    fn a_subcommand_row_applies_only_under_that_subcommand() {
        // The false positive this column exists to avoid: the effective program
        // is the same word whether the action mutates or reads, so a row keyed
        // on the program alone refuses the read half too.
        let table = [under("p", "move")];
        let matched = qualify(&table, "p", &["move", "a", "b"]).expect("the subcommand matched");
        assert_eq!(matched.consumed, 1, "the subcommand is not an operand");
        assert!(qualify(&table, "p", &["show"]).is_none());
        assert!(qualify(&table, "p", &[]).is_none());
        // First argument only, the limit the ported table also had: a global
        // option before the subcommand hides it, which under-denies.
        assert!(qualify(&table, "p", &["-C", "elsewhere", "move", "a", "b"]).is_none());
    }

    #[test]
    fn declaration_order_decides_between_two_subcommands_of_one_program() {
        // Two rows for one program are legal precisely because they are two
        // actions; each must resolve to its OWN row, since the redirect a deny
        // renders comes from it.
        let table = [under("p", "move"), under("p", "delete")];
        assert_eq!(
            qualify(&table, "p", &["delete", "x"])
                .expect("the second row applies")
                .verb
                .subcommand
                .as_deref(),
            Some("delete")
        );
        assert_eq!(
            qualify(&table, "p", &["move", "x"])
                .expect("the first row applies")
                .verb
                .subcommand
                .as_deref(),
            Some("move")
        );
    }

    #[test]
    fn a_flag_row_applies_only_when_one_of_its_flags_is_present() {
        let table = [behind("p", &["-q", "--qualify"])];
        for arguments in [
            &["-q", "x"][..],
            &["--qualify", "x"],
            // The value-bearing forms: a suffix after `.` and a value after `=`.
            &["-q.bak", "x"],
            &["--qualify=x", "y"],
            // Any listed spelling qualifies, in any position.
            &["expr", "--qualify", "x"],
        ] {
            assert!(
                qualify(&table, "p", arguments).is_some(),
                "must apply: {arguments:?}"
            );
        }
        // And the read half, which is the load-bearing direction: without the
        // flag this row must not fire at all.
        for arguments in [&["--version"][..], &["expr", "x"], &[]] {
            assert!(
                qualify(&table, "p", arguments).is_none(),
                "must not apply: {arguments:?}"
            );
        }
        // A longer flag that merely STARTS with the declared one is not it.
        assert!(qualify(&table, "p", &["-quiet", "x"]).is_none());
    }

    #[test]
    fn a_lookup_by_program_alone_never_satisfies_a_qualifier() {
        // The property `classify` being defined over `qualify` buys: a surface
        // that parses no argv (a write tool naming one path) cannot fire a row
        // declared about a command line.
        let table = [
            behind("p", &["-q"]),
            under("p", "move"),
            verb("plain", Effect::Write),
        ];
        assert!(classify(&table, "p").is_none());
        assert!(classify(&table, "plain").is_some());
    }

    #[test]
    fn the_operand_scope_defaults_to_every_operand() {
        // Absence resolves one way only, and it is the way that fails toward
        // refusing.
        assert_eq!(OperandScope::default(), OperandScope::All);
        assert_eq!(verb("p", Effect::Write).operand_scope(), OperandScope::All);
        assert_eq!(
            MutatingVerb {
                operands: Some(OperandScope::Last),
                ..verb("p", Effect::Write)
            }
            .operand_scope(),
            OperandScope::Last
        );
    }

    #[test]
    fn an_inert_qualifier_is_refused_rather_than_kept() {
        // Each of these loads clean and can never match — the same
        // present-and-inert gate the `effect` check refuses.
        let empty_flags = MutatingVerb {
            requires_flag: Some(Vec::new()),
            ..verb("p", Effect::Write)
        };
        let operand_as_flag = behind("p", &["notaflag"]);
        let two_word_flag = behind("p", &["-q x"]);
        let flag_as_subcommand = under("p", "-q");
        let two_word_subcommand = under("p", "a b");
        for row in [
            empty_flags,
            operand_as_flag,
            two_word_flag,
            flag_as_subcommand,
            two_word_subcommand,
        ] {
            let err = row.validate().unwrap_err();
            assert!(
                err.downcast_ref::<UsageError>().is_some(),
                "an inert qualifier is a usage error: {row:?}"
            );
        }
    }

    #[test]
    fn two_subcommands_of_one_program_are_not_a_duplicate_declaration() {
        // The duplicate rule keys on the PAIR. Two actions of one front-end are
        // two rows by design; the same pair twice is still the ambiguity the
        // original check refused.
        assert!(validate(&[under("p", "move"), under("p", "delete")]).is_ok());
        assert!(validate(&[under("p", "move"), under("p", "move")]).is_err());
        // A qualified row beside the bare program is also two distinct keys, and
        // declaration order decides which applies.
        assert!(validate(&[verb("p", Effect::Write), under("p", "move")]).is_ok());
    }

    #[test]
    fn the_source_bakes_in_no_verb() {
        // Non-negotiable rule 1, as a grep over this module's own source: which
        // programs mutate is the consumer's policy, so no real verb may appear
        // here as a literal. The tokens are assembled so the prose above — which
        // must be free to *discuss* the failure mode — is not itself a match.
        // The qualifier columns (CLOUD-442) widen this list rather than leave it
        // where it was: the columns exist so a consumer can declare a
        // subcommand- or flag-qualified verb, and the temptation they create is
        // to special-case the one program that needed them right here.
        let source = include_str!("verbs.rs");
        for baked in [
            ["\"", "rm\""].concat(),
            ["\"", "mv\""].concat(),
            ["\"", "dd\""].concat(),
            ["\"", "truncate\""].concat(),
            ["\"", "shred\""].concat(),
            ["\"", "cp\""].concat(),
            ["\"", "sed\""].concat(),
            ["\"", "git\""].concat(),
            ["\"", "install\""].concat(),
            ["\"", "-i\""].concat(),
            ["\"", "--in-place\""].concat(),
        ] {
            assert!(
                !source.contains(&baked),
                "verbs source hardcodes {baked}; the table comes from batten.toml"
            );
        }
    }
}
