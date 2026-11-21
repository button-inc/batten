use crate::config_model::HookCeiling as Ceiling;

/// Refuse a ceiling nothing could satisfy.
///
/// # Errors
///
/// When `max_tokens` is zero — no hook could speak at all — or when
/// `max_repeats` is zero, which refuses a hook's FIRST emission and so silences
/// the finding rather than its restatement.
pub fn validate(ceiling: Option<&Ceiling>) -> Result<(), String> {
    let Some(declared) = ceiling else {
        return Ok(());
    };
    if declared.max_tokens == 0 {
        return Err(
            "`[hook_output] max_tokens = 0` refuses every hook that speaks at all — remove the \
             table to leave hook output unbounded, or name a ceiling a session can fit inside"
                .to_owned(),
        );
    }
    if declared.max_repeats == 0 {
        return Err(
            "`[hook_output] max_repeats = 0` refuses a hook's FIRST emission, which silences the \
             finding rather than its restatement; 1 is the floor — say it once"
                .to_owned(),
        );
    }
    Ok(())
}
