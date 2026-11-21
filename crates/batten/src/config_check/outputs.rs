use crate::config_model::OutputPattern;
use crate::error::UsageError;

/// Refuse a malformed `[[exec_pattern]]` table at load, so a typo cannot sit inert.
///
/// # Errors
///
/// As [`validate_named`].
pub fn validate(patterns: &[OutputPattern]) -> anyhow::Result<()> {
    validate_named(patterns, "exec_pattern")
}

/// Refuse a malformed `[[verify_environment_pattern]]` table at load.
///
/// # A SECOND ENTRY POINT OVER ONE IMPLEMENTATION, and both reasons are real
///
/// The checks are identical — same type, same four ways to be malformed — so the
/// body is [`validate_named`] and this adds none of its own. What it adds is a
/// NAME, twice over.
///
/// It names the table in the refusal. `validate` spelled `exec_pattern` into
/// every message, so the second table's malformed row would have reported a row
/// in a table the author had not touched — a pointer to the wrong file, which is
/// worse than no pointer.
///
/// And it names the table to `config.rs`'s census, which resolves each declared
/// table to its validator BY THE CALL STRING. Two tables sharing
/// `outputs::validate(` are one call site to that gate: it finds the first,
/// reads the class wrapping it, and reports the second as unwrapped. A distinct
/// entry point is what makes the census able to see both.
///
/// # Errors
///
/// As [`validate_named`].
pub fn validate_environment(patterns: &[OutputPattern]) -> anyhow::Result<()> {
    validate_named(patterns, "verify_environment_pattern")
}

/// Refuse a malformed pattern table at load, so a typo cannot sit inert.
///
/// `table` is the caller's own table name, carried into every message so a
/// refusal points at the file and row an author has to edit.
///
/// # Errors
///
/// Returns a [`UsageError`] for an empty id, pattern or reason, or a duplicate id.
pub fn validate_named(patterns: &[OutputPattern], table: &str) -> anyhow::Result<()> {
    let mut seen: Vec<&str> = Vec::with_capacity(patterns.len());
    for pattern in patterns {
        if pattern.id.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "{table}: id must not be empty — it is what a match is reported as"
            )));
        }
        if pattern.pattern.is_empty() {
            return Err(UsageError::raise(format!(
                "{table} {}: pattern must not be empty — an empty literal matches every run",
                pattern.id
            )));
        }
        if pattern.reason.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "{table} {}: reason is required — a promoted exit code is all the caller gets back",
                pattern.id
            )));
        }
        if seen.contains(&pattern.id.as_str()) {
            return Err(UsageError::raise(format!(
                "{table} {}: declared twice",
                pattern.id
            )));
        }
        seen.push(&pattern.id);
    }
    Ok(())
}
