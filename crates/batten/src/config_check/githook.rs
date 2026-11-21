use crate::error::UsageError;

/// Reject a `[hook.git]` row whose name is no git hook, or whose argv is empty
/// (CLOUD-2339): either would load clean and run nothing at the moment the
/// operator believes it guards.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) naming the row.
pub fn validate(rows: &std::collections::BTreeMap<String, Vec<String>>) -> anyhow::Result<()> {
    for (name, argv) in rows {
        if !crate::config_model::is_git_hook(name) {
            return Err(UsageError::raise(format!(
                "hook.git {name}: not a githooks(5) name, so git never runs it"
            )));
        }
        if argv.first().is_none_or(String::is_empty) {
            return Err(UsageError::raise(format!(
                "hook.git {name}: an empty argv runs nothing"
            )));
        }
    }
    Ok(())
}
