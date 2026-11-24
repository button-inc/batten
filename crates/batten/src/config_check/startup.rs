use crate::config_model::{Rule, Startup};
use crate::error::UsageError;
use anyhow::Result;

/// Refuse a row the engine cannot act on, at LOAD rather than at the first run.
///
/// An empty `check` is the one that matters: [`ran_clean`] would answer
/// could-not-look forever, so the row would report a failure nobody can fix and
/// its repair would never run. Refusing it at load says which row and why, once,
/// instead of once per session — the same direction `[[pattern]]`'s load-time
/// refusal takes one surface over.
///
/// # Errors
///
/// A [`UsageError`] naming the offending row's id.
pub fn validate(rows: &[Startup]) -> Result<()> {
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for row in rows {
        if row.preset.is_some() {
            // A DERIVED ROW CARRIES NO ARGV OF ITS OWN (CLOUD-2633): a hand-written
            // `check` beside the preset's would be two authorities over one
            // question, and the reader could not tell which one ran.
            if !row.check.is_empty()
                || row.repair.is_some()
                || row.decided_by != crate::config_model::Decided::ExitStatus
            {
                return Err(UsageError::raise(format!(
                    "[[startup]] {}: `preset` derives `check`, `repair` and `decided_by` \
                     from the preset's install, so the row may not also declare them",
                    row.id
                )));
            }
        } else if row.check.is_empty() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `check` is empty, so the row could never decide anything",
                row.id
            )));
        }
        if row.repair.as_ref().is_some_and(Vec::is_empty) {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `repair` is present and empty — omit the key for a \
                 diagnose-only row rather than declaring a repair that runs nothing",
                row.id
            )));
        }
        if row.gloss.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `gloss` is empty, and the report is pointer-only — this is \
                 the one place the row's meaning can be written down",
                row.id
            )));
        }
        if !seen.insert(row.id.as_str()) {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: declared twice — one id, one row, or a report names a \
                 verdict a reader cannot trace back",
                row.id
            )));
        }
    }
    Ok(())
}

/// Refuse a preset install the engine could not derive, or would derive wrong
/// (CLOUD-2633), at LOAD and naming the row.
///
/// Cross-table, because the parameter lives on the `[[rule]]` that enables the
/// preset and the position lives on the `[[startup]]` row that places it: each
/// without the other is a declaration nothing acts on.
///
/// # Errors
///
/// A [`UsageError`] naming the offending row.
pub fn validate_installs(rules: &[Rule], rows: &[Startup]) -> Result<()> {
    let mut carriers: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for rule in rules {
        if rule.environments.is_none() && rule.install_env.is_empty() {
            continue;
        }
        let name = rule.preset.as_deref().unwrap_or_default();
        let Some(install) = crate::preset_catalog::MANIFESTS
            .iter()
            .find(|manifest| manifest.name == name)
            .and_then(|manifest| manifest.install.as_ref())
        else {
            return Err(UsageError::raise(format!(
                "rule {}: `environments` and `install_env` parameterise a preset's install, \
                 and the preset `{name}` declares none",
                rule.id
            )));
        };
        let Some(environments) = rule.environments.as_deref() else {
            return Err(UsageError::raise(format!(
                "rule {}: `install_env` qualifies `environments`, which this row omits",
                rule.id
            )));
        };
        environment_names(&rule.id, environments, install.separator)?;
        if let Some(bad) = rule.install_env.iter().find(|pair| {
            let name = pair.split_once('=').map_or("", |(name, _)| name);
            !is_variable_name(name) || name == install.selector
        }) {
            return Err(UsageError::raise(format!(
                "rule {}: `install_env` entry `{bad}` is not a `NAME=VALUE` assignment, or sets \
                 `{}`, which `environments` owns",
                rule.id, install.selector
            )));
        }
        if let Some(first) = carriers.insert(name, rule.id.as_str()) {
            return Err(UsageError::raise(format!(
                "rule {}: `environments` for the preset `{name}` is already declared by rule \
                 {first}; one list, or the install could not say which it ran",
                rule.id
            )));
        }
    }
    for row in rows {
        let Some(name) = row.preset.as_deref() else {
            continue;
        };
        if carriers.remove(name).is_none() {
            return Err(UsageError::raise(format!(
                "[[startup]] {}: `preset = \"{name}\"` places an install that no `[[rule]]` \
                 enabling `{name}` parameterises with `environments`, or that a row above \
                 already placed",
                row.id
            )));
        }
    }
    if let Some((name, rule)) = carriers.into_iter().next() {
        return Err(UsageError::raise(format!(
            "rule {rule}: `environments` declares an install for the preset `{name}` and no \
             `[[startup]]` row with `preset = \"{name}\"` places it, so it would never run"
        )));
    }
    Ok(())
}

/// Refuse an environment list that is empty, repeats a name, or holds a name
/// the tool could not read as ONE environment.
fn environment_names(rule: &str, environments: &[String], separator: &str) -> Result<()> {
    if environments.is_empty() {
        return Err(UsageError::raise(format!(
            "rule {rule}: `environments` is empty; omit the key rather than declaring an \
             install of nothing beyond the base configuration"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for name in environments {
        // The separator is the one that splits the selector, so a name holding
        // it would install two environments under one declared name.
        let malformed = name.is_empty()
            || name.contains(separator)
            || !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if malformed {
            return Err(UsageError::raise(format!(
                "rule {rule}: environment `{name}` is not one name: letters, digits, `-` and `_`"
            )));
        }
        if !seen.insert(name.as_str()) {
            return Err(UsageError::raise(format!(
                "rule {rule}: environment `{name}` is listed twice"
            )));
        }
    }
    Ok(())
}

/// A POSIX environment variable name.
fn is_variable_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    /// Fails by: a leading `_` refused, or a leading digit admitted.
    #[test]
    fn a_variable_name_starts_with_a_letter_or_an_underscore() {
        assert!(super::is_variable_name("_MISE_ENV"));
        assert!(super::is_variable_name("MISE_ENV"));
        assert!(!super::is_variable_name("1MISE"));
        assert!(!super::is_variable_name(""));
    }

    /// A config enabling `mise` with `rule_tail` appended to its row, and the
    /// placing `[[startup]]` row when `placed`.
    fn config(rule_tail: &str, placed: bool) -> String {
        let startup = if placed {
            "\n[[startup]]\nid = \"toolchain\"\ngloss = \"the listed environments are installed\"\npreset = \"mise\"\n"
        } else {
            ""
        };
        format!(
            "version = 1\n\n[[rule]]\nid = \"task reach loose\"\nkind = \"policy\"\n\
             scope = \"mediated_call\"\npreset = \"mise\"\nseverity = \"warn\"\n{rule_tail}{startup}"
        )
    }

    fn refusal(rule_tail: &str, placed: bool) -> String {
        format!(
            "{:#}",
            crate::config::parse(&config(rule_tail, placed), "test").unwrap_err()
        )
    }

    /// The anti-vacuity half: the refusals below are not a key every config
    /// fails on.
    #[test]
    fn an_environment_list_parses_and_reaches_the_rule() {
        let parsed = crate::config::parse(
            &config(
                "environments = [\"agent\"]\ninstall_env = [\"MISE_LOCKED=1\"]\n",
                true,
            ),
            "test",
        )
        .unwrap();
        assert_eq!(
            parsed.rules[0].environments.as_deref(),
            Some(&[String::from("agent")][..])
        );
        assert_eq!(parsed.startup[0].preset.as_deref(), Some("mise"));
    }

    #[test]
    fn an_empty_environment_list_is_refused() {
        assert!(refusal("environments = []\n", true).contains("is empty"));
    }

    #[test]
    fn a_name_that_is_not_one_environment_is_refused() {
        // The separator would install two environments under one name.
        assert!(refusal("environments = [\"agent,ci\"]\n", true).contains("not one name"));
        assert!(refusal("environments = [\"\"]\n", true).contains("not one name"));
        assert!(refusal("environments = [\"agent\", \"agent\"]\n", true).contains("twice"));
    }

    #[test]
    fn an_install_flag_may_not_name_the_selector_or_be_no_assignment() {
        let selector = refusal(
            "environments = [\"agent\"]\ninstall_env = [\"MISE_ENV=ci\"]\n",
            true,
        );
        assert!(selector.contains("MISE_ENV=ci"), "{selector}");
        let bare = refusal(
            "environments = [\"agent\"]\ninstall_env = [\"MISE_LOCKED\"]\n",
            true,
        );
        assert!(bare.contains("NAME=VALUE"), "{bare}");
    }

    #[test]
    fn a_list_nothing_places_and_a_place_nothing_lists_are_both_refused() {
        assert!(refusal("environments = [\"agent\"]\n", false).contains("never run"));
        assert!(refusal("", true).contains("no `[[rule]]`"));
    }

    #[test]
    fn a_preset_that_installs_nothing_takes_no_environments() {
        let text = "version = 1\n\n[[rule]]\nid = \"pin table other\"\nkind = \"policy\"\n\
                    scope = \"mediated_call\"\npreset = \"pinned-toolchain\"\nseverity = \"warn\"\n\
                    environments = [\"agent\"]\n";
        let err = format!("{:#}", crate::config::parse(text, "test").unwrap_err());
        assert!(err.contains("declares none"), "{err}");
    }

    #[test]
    fn a_placed_row_may_not_also_write_its_own_argv() {
        // The `[[startup]]` row is the last table, so this key lands on it.
        let text = config("environments = [\"agent\"]\n", true) + "check = [\"true\"]\n";
        let err = format!("{:#}", crate::config::parse(&text, "test").unwrap_err());
        assert!(err.contains("may not also declare"), "{err}");
    }

    /// Fails by: the `_` arm of the name alphabet inverted, so an underscore
    /// is refused and any other punctuation admitted.
    #[test]
    fn an_environment_name_admits_underscore_and_no_other_punctuation() {
        let names = |name: &str| super::environment_names("r", &[name.to_owned()], ":");
        assert!(names("ci_agent").is_ok());
        assert!(names("ci.agent").is_err());
    }
}
