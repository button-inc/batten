use crate::config_model::Channel;

/// Refuse a ceiling nothing could satisfy.
///
/// # Errors
///
/// When the declared ceiling is zero: it would suppress every advisory including
/// the shortest, which is a channel switched off wearing a budget's clothes.
pub fn validate(channel: Option<&Channel>) -> Result<(), String> {
    match channel {
        Some(declared) if declared.max_tokens == 0 => Err(
            "`[advisory] max_tokens = 0` suppresses every advisory the channel could carry — \
             remove the table to leave the channel unbounded, or name a ceiling something can \
             fit inside"
                .to_owned(),
        ),
        _ => Ok(()),
    }
}
