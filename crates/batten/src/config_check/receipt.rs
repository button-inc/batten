use crate::error::UsageError;

use anyhow::Result;

/// Validate a check name for use as an identity field and a filename
/// component: ASCII alphanumeric first, then alphanumeric plus `.`, `_`, `-`.
pub(crate) fn validate_check_name(check: &str) -> Result<()> {
    let mut chars = check.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if first_ok && rest_ok {
        Ok(())
    } else {
        Err(UsageError::raise(format!(
            "check name {check:?} is not a valid identifier (ASCII alphanumeric, then alphanumeric or `.`, `_`, `-`)"
        )))
    }
}

/// Refuse a `[receipt] verified_by` naming a check no receipt can ever be
/// written for.
///
/// # AT LOAD, BECAUSE THE ALTERNATIVE IS A CONFIG THAT IS PERMANENTLY UNUSABLE
///
/// `receipt record` and `receipt status` already refuse these names, and nothing
/// held the config table to the same rule (review of #848). So
/// `verified_by = ["fmt check"]` loaded clean, `receipt record "fmt check"`
/// exited `1` with *"not a valid identifier"*, no receipt could ever exist, and
/// [`run_verified`] — which validates nothing and hashes the name straight into
/// a path — reported `NOT verified: <head> fmt check missing` forever. The
/// refusal pointed at a missing receipt rather than at the unwritable name that
/// made it missing, which is the inert-typo class every other declared table in
/// `config::validate_tables` is refused at load for.
///
/// Fail-closed either way; what changes is that the diagnosis names the cause.
///
/// # Errors
///
/// [`crate::UsageError`] naming the first offending check.
pub fn validate_verified_by(checks: &[String]) -> Result<()> {
    for check in checks {
        validate_check_name(check)?;
    }
    Ok(())
}

/// Whether `subject` is safe to use as one path component under the receipt
/// store (CLOUD-987).
///
/// **Refused, never rewritten.** The subject of a [`ReceiptKey::Named`] receipt
/// comes out of the mediated call's own arguments, so it is the least trusted
/// string in the envelope that this engine turns into a filename. Rewriting a bad
/// one — stripping separators, replacing `..` — would file two different subjects
/// under one receipt and let a fresh read of A authorise a stale write to B,
/// which is precisely the confusion `ReceiptKey::Named` exists to prevent. So a
/// value that is not already a single safe component is not a subject at all.
///
/// The bound is structural rather than a format: what a tracker's identifiers
/// look like is a consumer fact (non-negotiable rule 1), and a row that wants to
/// insist on a shape has `when_present` and its own selection for that. What the
/// core knows is that a path component may not be empty, may not be `.` or `..`,
/// may not contain a separator or a NUL, and may not be unboundedly long.
///
/// `pub(crate)` since CLOUD-1024: the mint that WRITES a named receipt has to
/// refuse exactly the subjects the reader refuses, or the two halves disagree
/// about which filenames exist.
pub(crate) fn safe_subject(subject: &str) -> bool {
    !subject.is_empty()
        && subject != "."
        && subject != ".."
        && subject.len() <= 128
        && !subject.contains(|ch: char| ch == '/' || ch == '\\' || ch == '\0' || ch.is_control())
}
