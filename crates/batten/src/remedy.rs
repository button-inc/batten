//! Whether a rule row DECLARES its remedy — `fix` or `no_fix_reason`, exactly one
//! (CLOUD-1576).
//!
//! House style §9 pairs every condemnation with its repair, and the repair half
//! sat empty: zero rows declared a `fix`, and most declared no reason either. A
//! gate that only points costs the reader read → locate → decide → edit on every
//! finding; the row saying which of those a machine could have done is what this
//! module holds rows to.
//!
//! # Two tiers, split by what refusing costs
//!
//! * [`malformed`] is a LOAD error, called from `Rule::validate`. Both keys, or a
//!   reason that is blank, is a row that says two contradictory things or says
//!   nothing while reading as an answer. No config is well-formed with either.
//! * [`classified`] is a `config lint` smell, together with a row that declares
//!   neither key. Refusing those at load would refuse every consumer config that
//!   predates this column, which is the class of breakage §8's
//!   forward-compatibility contract exists to prevent. A smell names them, and
//!   `verify` holds this repository to zero.
//!
//! # The reason's grammar is `class N (<substrate>): <why>`
//!
//! There are three remedy classes, by the substrate a repair would be written in:
//!
//! 1. **config codemod**: a format-preserving edit of a config file.
//! 2. **source codemod**: a lossless rewrite of source.
//! 3. **prose + traversal**: a judgement no command makes, routed by the refusal's
//!    own remedy text.
//!
//! The parenthesised substrate names what is MISSING, so a reason goes stale in a
//! way a reader can see once that substrate lands. It is the one part of the
//! row's claim that a later change can falsify.

/// Why a row's remedy columns are malformed, or `None` when they are not.
///
/// Returns a `'static` sentence rather than an error, so the caller owns the
/// rule id and the exit class (`UsageError`, exit `1`).
#[must_use]
//MUTANT-SUITE crates/batten/tests/it/fix_declared.rs
//MUTANT fix-and-reason-both-admitted|s@^    if fix.is_some() && no_fix_reason.is_some() {$@    if false {@|a_row_with_both_keys_is_malformed
//MUTANT empty-fix-reason-admitted|s@^    if no_fix_reason.map(str::trim).is_some_and(str::is_empty) {$@    if false {@|a_blank_reason_is_malformed
pub fn malformed(fix: Option<&str>, no_fix_reason: Option<&str>) -> Option<&'static str> {
    if fix.is_some() && no_fix_reason.is_some() {
        return Some(
            "`fix` and `no_fix_reason` are alternatives; a row carries exactly one, never both",
        );
    }
    if no_fix_reason.map(str::trim).is_some_and(str::is_empty) {
        return Some(
            "`no_fix_reason` is blank; a reason that says nothing reads as an answer and is \
             none — name the remedy class and the missing substrate, `class N (<substrate>): <why>`",
        );
    }
    None
}

/// Whether `reason` opens with `class N (<substrate>): ` and has text after it,
/// where N is 1, 2 or 3 and the substrate is non-blank.
#[must_use]
pub fn classified(reason: &str) -> bool {
    let Some(rest) = reason.strip_prefix("class ") else {
        return false;
    };
    let Some(rest) = rest
        .strip_prefix('1')
        .or_else(|| rest.strip_prefix('2'))
        .or_else(|| rest.strip_prefix('3'))
    else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(" (") else {
        return false;
    };
    let Some((substrate, why)) = rest.split_once("): ") else {
        return false;
    };
    !substrate.trim().is_empty() && !substrate.contains('(') && !why.trim().is_empty()
}
