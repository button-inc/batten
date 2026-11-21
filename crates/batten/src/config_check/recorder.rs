use crate::config_model::{Program, Read, RecorderDeclared as Declared, Value};
use anyhow::Result;
use std::collections::BTreeMap;

/// Refuse, at LOAD, every recorder that could not have written what it claims.
///
/// The refusals below are all of the same kind and it is the kind this repository
/// keeps choosing: a declaration naming something the tree does not carry is a
/// gate that runs, resolves nothing, and reports clean. A recorder is worse than
/// a rule that way, because it has no verdict at all — a column that silently
/// renders `-` forever looks exactly like a column that looked and could not see.
///
/// # Errors
///
/// Returns a [`crate::error::UsageError`] (→ exit `1`) naming the recorder, the
/// column and the missing id.
pub fn validate(
    recorders: &[Declared],
    programs: &BTreeMap<String, Program>,
    patterns: &std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    for recorder in recorders {
        validate_shape(recorder, &mut seen, patterns)?;
        if let Some(recorded) = &recorder.requires_recorded {
            for value in recorded.matches.values() {
                validate_value(
                    &recorder.name,
                    "requires-recorded",
                    value,
                    programs,
                    patterns,
                )?;
            }
        }
        for column in &recorder.columns {
            for value in [
                Some(&column.value),
                column.minus.as_ref(),
                column.without.as_ref(),
            ]
            .into_iter()
            .flatten()
            {
                validate_value(&recorder.name, &column.name, value, programs, patterns)?;
            }
        }
    }
    Ok(())
}

/// The shape refusals, split out of [`validate`] when it hit its own line
/// ceiling. The seam is the one the function already had: everything here is a
/// property of the ROW — its name, its selectors, its column count — and
/// everything left behind walks the expressions inside a column.
pub(crate) fn validate_shape(
    recorder: &Declared,
    seen: &mut std::collections::BTreeSet<String>,
    patterns: &std::collections::BTreeSet<String>,
) -> Result<()> {
    if recorder.name.trim().is_empty() {
        return Err(crate::error::UsageError::raise(
            "a `[[recorder]]` row carries an empty `name`, so nothing can point at it",
        ));
    }
    if recorder.record.trim().is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} names no `record`, so it would write nowhere",
            recorder.name
        )));
    }
    if !seen.insert(recorder.name.clone()) {
        return Err(crate::error::UsageError::raise(format!(
            "two `[[recorder]]` rows are named {:?}, so a finding could not say \
             which one wrote a line",
            recorder.name
        )));
    }
    if recorder.tool.trim().is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} selects on an empty `tool`, which matches nothing",
            recorder.name
        )));
    }
    // A SELECTOR IS NOT A GLOB, and a row that thinks it is fails SILENTLY.
    //
    // `rules::selects_tool_name` matches the whole name or its final
    // `__`-delimited segment (CLOUD-178, so a connector renamed over its
    // lifetime still matches). A `*save_issue` written by habit from a shell
    // `case` pattern therefore matches nothing at all — and a recorder that
    // never fires is byte-identical, on every surface, to a tool nobody
    // called. Measured here: the whole table was dead and only the cases
    // asserting a row WAS written could see it, because the ones asserting
    // none passed vacuously.
    //
    // Refused at load for that asymmetry: the failure has no loud direction
    // at runtime, so the only place it can be caught is before the run.
    if let Some(found) = recorder
        .tool
        .find(['*', '?', '['])
        .and_then(|at| recorder.tool.get(at..=at))
    {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} selects on tool {:?}, which carries {found:?} — a tool \
             selector is matched whole or by its final `__`-delimited segment, \
             never as a glob, so this row would match nothing and record silently",
            recorder.name, recorder.tool
        )));
    }
    for (path, pattern) in &recorder.requires_input_matching {
        if path.trim().is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} matches on an empty input path, which reads nothing \
                 and so never selects",
                recorder.name
            )));
        }
        if !patterns.contains(pattern) {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} selects on input {path:?} matching pattern {pattern:?}, \
                 which no `[[pattern]]` row declares — the row would never fire and \
                 a recorder that never fires is indistinguishable from a tool nobody \
                 called",
                recorder.name
            )));
        }
    }
    if recorder.columns.is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {:?} declares no columns, so it would append blank lines",
            recorder.name
        )));
    }
    if let Some(recorded) = &recorder.requires_recorded {
        if recorded.matches.is_empty() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {:?} gates on an empty `requires-recorded`, which every \
                 existing line satisfies — a precondition matching anything is not one",
                recorder.name
            )));
        }
        for column in recorded.matches.keys() {
            if *column >= recorder.columns.len() {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {:?} gates on column {column} of an existing line, but \
                     it declares only {} column(s) — the comparison could never hold",
                    recorder.name,
                    recorder.columns.len()
                )));
            }
        }
    }
    Ok(())
}

/// Every id one expression names, checked against what the config declares.
pub(crate) fn validate_value(
    recorder: &str,
    column: &str,
    value: &Value,
    programs: &BTreeMap<String, Program>,
    patterns: &std::collections::BTreeSet<String>,
) -> Result<()> {
    match value {
        Value::Literal(_)
        | Value::Branch
        | Value::Result(_)
        | Value::Input(_)
        | Value::Inputs(_)
        | Value::Wrap { .. } => Ok(()),
        Value::Object(fields) => fields
            .values()
            .try_for_each(|value| validate_value(recorder, column, value, programs, patterns)),
        Value::Section {
            from,
            label,
            select,
        } => {
            for id in [label, select] {
                if !patterns.contains(id) {
                    return Err(crate::error::UsageError::raise(format!(
                        "recorder {recorder:?} column {column:?} narrows on pattern {id:?}, \
                         which no `[[pattern]]` row declares — an inline regex is refused here \
                         for the reason a policy module's is, so the id must exist"
                    )));
                }
            }
            validate_value(recorder, column, from, programs, patterns)
        }
        Value::Program { run, stdin, read } => {
            if !programs.contains_key(run) {
                return Err(crate::error::UsageError::raise(format!(
                    "recorder {recorder:?} column {column:?} runs program {run:?}, \
                     which no `[program]` row declares"
                )));
            }
            validate_status_table(recorder, column, run, read)?;
            validate_value(recorder, column, stdin, programs, patterns)
        }
        // NO ID TO RESOLVE, and that is the point of the variant rather than a
        // gap in this function: `ask` is a closed enum, so serde has already
        // refused an authority no build carries. What still needs checking is the
        // status table, which is the consumer's either way.
        Value::Authority { ask, stdin, read } => {
            validate_status_table(recorder, column, &format!("{ask:?}").to_lowercase(), read)?;
            validate_value(recorder, column, stdin, programs, patterns)
        }
    }
}

/// A `read = { status = … }` table that can actually decide something.
///
/// Shared by the spawning and the compiled arms: an empty table records
/// could-not-look for every status, and a key that is not an exit code can never
/// match one.
pub(crate) fn validate_status_table(
    recorder: &str,
    column: &str,
    source: &str,
    read: &Read,
) -> Result<()> {
    let Read::Status(map) = read else {
        return Ok(());
    };
    if map.is_empty() {
        return Err(crate::error::UsageError::raise(format!(
            "recorder {recorder:?} column {column:?} reads {source:?}'s status through an empty \
             table, so every status would record as could-not-look"
        )));
    }
    for status in map.keys() {
        if status.parse::<i32>().is_err() {
            return Err(crate::error::UsageError::raise(format!(
                "recorder {recorder:?} column {column:?} maps status {status:?}, which is not an \
                 exit code"
            )));
        }
    }
    Ok(())
}
