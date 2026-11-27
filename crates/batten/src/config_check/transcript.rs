use crate::config_model::TranscriptConfig;
use crate::error::UsageError;

use anyhow::Result;

/// Validate the table at load, the way every other config table is.
///
/// Takes an `Option` to match [`crate::config_check::budget::validate`]'s signature: `[budget]`
/// and `[transcript]` are both tables rather than lists, so neither is reached by
/// the `Vec<T>` census in `config.rs`, and both are called explicitly from
/// `parse_ungated` for that reason.
///
/// # Errors
///
/// [`UsageError`] when a declared path is empty — a key present and blank is a
/// different claim from a key absent, and the blank one is a mistake rather than
/// a repository opting out. Left unchecked it would join to the repository root
/// and be read as a directory, which surfaces as "undecodable transcript".
pub fn validate(config: Option<&TranscriptConfig>) -> Result<()> {
    let Some(config) = config else {
        return Ok(());
    };
    if config.path.as_deref().is_some_and(str::is_empty) {
        return Err(UsageError::raise(
            "transcript.path: declared but empty; omit the key to opt out".to_owned(),
        ));
    }
    Ok(())
}
