use crate::Result;
use crate::config_model::{McpConfig, McpSource as Source};
use crate::error::UsageError;

use std::path::Path;

/// Refuse a `[mcp.source.credential]` row that cannot mean one thing.
///
/// **At LOAD rather than at dispatch**, for the reason every other shape rule
/// here is: a row naming neither source names nothing, and a row naming both is
/// two answers to one question. Either would resolve to no header and dispatch an
/// unauthenticated call that reads as the server refusing — a dead gate wearing a
/// 401's clothes.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) naming the source id and which key is at fault.
/// **Never a variable's VALUE** — the names are config and the values are not.
pub(crate) fn validate_credential(source: &Source) -> Result<()> {
    let Some(row) = &source.credential else {
        return Ok(());
    };
    let id = &source.id;
    if row.header.trim().is_empty() {
        return Err(UsageError::raise(format!(
            "mcp: source {id:?} declares a credential with an empty `header`; a credential with \
             nowhere to go is a call that authenticates with nothing"
        )));
    }
    let named: Vec<&String> = [&row.env, &row.file_from, &row.helper]
        .into_iter()
        .flatten()
        .collect();
    match named.as_slice() {
        [] => Err(UsageError::raise(format!(
            "mcp: source {id:?} declares a credential naming none of `env`, `file_from` or \
             `helper`; a row that names nothing resolves to nothing and would dispatch \
             unauthenticated"
        ))),
        [_, _, ..] => Err(UsageError::raise(format!(
            "mcp: source {id:?} declares a credential naming more than one of `env`, `file_from` \
             and `helper`; one row names one source, or which one the engine spends depends on \
             the order it reads them"
        ))),
        [name] if name.trim().is_empty() => Err(UsageError::raise(format!(
            "mcp: source {id:?} declares a credential naming an empty variable or key; it is a \
             NAME, never a value"
        ))),
        _ => Ok(()),
    }
}

/// Refuse a malformed `[mcp]` table at load.
///
/// At load rather than at dispatch, for the reason house style §8 gives: a config
/// fault must be reported by `config lint` and `doctor` rather than discovered by
/// the one call that needed it.
///
/// # Errors
///
/// [`UsageError`] (→ exit `1`) for an empty or duplicated id, an empty root name,
/// a path that would escape its root, a duplicated method, a field list that does
/// not match the reduction it is written for, or a credential row naming neither
/// variable or both.
pub fn validate(config: &McpConfig) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for source in &config.sources {
        if source.id.trim().is_empty() {
            return Err(UsageError::raise(
                "mcp: a `[[mcp.source]]` row needs a non-empty `id`; it is the only name a report \
                 may carry, because the resolved path is a machine's home directory",
            ));
        }
        if source
            .root
            .as_ref()
            .is_some_and(|root| root.trim().is_empty())
        {
            return Err(UsageError::raise(format!(
                "mcp: source {:?} declares an empty `root`; it is the NAME of an environment \
                 variable, and an empty one would resolve the path against the process's working \
                 directory. Omit the key for a repository-relative path",
                source.id
            )));
        }
        if source.base.is_some() && source.root.is_some() {
            return Err(UsageError::raise(format!(
                "mcp: source {:?} declares both `base` and `root`; one row has one base, or which \
                 directory the path resolves beneath depends on the order they are read",
                source.id
            )));
        }
        if escapes(&source.path) {
            return Err(UsageError::raise(format!(
                "mcp: source {:?} needs a `path` that is relative and stays beneath its root; an \
                 absolute path or a `..` component would read outside the root the row declared",
                source.id
            )));
        }
        // THE PLACEHOLDER'S SYNTAX AT LOAD, its VALUE at dispatch. A malformed
        // `${` is the author's typo and belongs to `config lint`; what a variable
        // happens to hold on this host is not knowable here, which is why
        // `escapes` runs a second time over the expanded path.
        if let Err(err) = placeholders(&source.path) {
            return Err(UsageError::raise(format!(
                "mcp: source {:?} has an unusable `path`: {err}",
                source.id
            )));
        }
        if seen.contains(&source.id.as_str()) {
            return Err(UsageError::raise(format!(
                "mcp: source id {:?} is declared twice; one id names one file, or which file the \
                 engine reads depends on row order",
                source.id
            )));
        }
        validate_endpoint_selectors(source)?;
        validate_credential(source)?;
        seen.push(&source.id);
    }
    // A PERMISSION ALIAS NO SELECTOR DECLARES CAN NEVER RESOLVE, so it would read
    // as a governed server while translating nothing — refused here rather than
    // discovered as a prompt that never went away.
    for alias in &config.permission_aliases {
        if !config
            .sources
            .iter()
            .any(|source| source.endpoint_contains.contains_key(alias))
        {
            return Err(UsageError::raise(format!(
                "mcp: `permission_aliases` names {alias:?}, which no `[[mcp.source]]` row's \
                 `endpoint_contains` declares; the endpoint is the only thing that identifies a \
                 renamed server, so this name could never be resolved"
            )));
        }
    }

    Ok(())
}

/// One piece of a declared path: text as written, or a variable to expand.
pub(crate) enum Part<'a> {
    /// Text that reaches the resolved path unchanged.
    Literal(&'a str),
    /// A `${NAME}` placeholder, by name.
    Variable(&'a str),
}

/// Check a declared path's placeholder SYNTAX, touching no environment.
///
/// The load-time half of [`expand`], and it is a separate entry point rather than
/// a flag because the two questions have different homes: a malformed `${` is the
/// author's typo and `config lint` must report it on every host, while what a
/// variable holds is knowable only where the call is made.
///
/// # Errors
///
/// As [`parts`].
pub(crate) fn placeholders(path: &str) -> Result<()> {
    parts(path).map(|_| ())
}

/// Split a declared path into literals and `${NAME}` placeholders.
///
/// # Errors
///
/// A [`UsageError`] (→ exit `1`) for an unclosed `${`, or a name that is not
/// `[A-Za-z_][A-Za-z0-9_]*`. Reading either as a literal would resolve a path
/// nobody wrote, which is the failure this refuses rather than tolerates.
pub(crate) fn parts(path: &str) -> Result<Vec<Part<'_>>> {
    let mut found = Vec::new();
    let mut rest = path;
    while let Some(open) = rest.find("${") {
        if open > 0 {
            found.push(Part::Literal(&rest[..open]));
        }
        let after = &rest[open + 2..];
        let close = after.find('}').ok_or_else(|| {
            UsageError::raise(format!(
                "path {path:?} opens `${{` and never closes it; a placeholder that does not end \
                 cannot name a variable"
            ))
        })?;
        let name = &after[..close];
        if !name
            .chars()
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_')
            || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            return Err(UsageError::raise(format!(
                "path {path:?} names {name:?}, which is not an environment variable name"
            )));
        }
        found.push(Part::Variable(name));
        rest = &after[close + 1..];
    }
    if !rest.is_empty() {
        found.push(Part::Literal(rest));
    }
    Ok(found)
}

/// Whether a declared path would leave the root it is resolved beneath.
///
/// [`crate::facts::Rooted::escapes`]'s predicate, and it is spelled here rather
/// than borrowed because the two families' rows are different types and sharing
/// the check would mean sharing the type. The rule is the same one: rooted, or
/// any upward component.
///
/// **Run TWICE since CLOUD-1251's expansion landed**: once at load over the
/// literal, and again over the EXPANDED path, because a variable's value is
/// runtime input. A row spelling `${ID}.json` passes the load-time check whatever
/// `ID` turns out to hold, so an `ID` of `../../etc` would otherwise walk out of
/// the base the row declared — the one place this feature could have become a
/// file-read primitive.
///
/// # `is_absolute` IS THE WRONG QUESTION, and it is wrong in the dangerous
/// direction
///
/// `Path::is_absolute` is platform-dependent, and on Windows it answers **false**
/// for `/etc/passwd`: that path has a root but no drive prefix, which Rust calls
/// relative. `Path::join` does not agree — `base.join("/etc/passwd")` there
/// discards the base's own path and yields `C:\etc\passwd`, outside the root the
/// row declared. So the predicate would have admitted exactly the declaration it
/// exists to refuse, on one platform, silently.
///
/// Measured rather than reasoned: this shipped, `mise run verify` passed —
/// `cross-check` TYPE-checks the Windows target and never runs a test there — and
/// the Windows job in CI is what went red. Enumerating the components asks the
/// portable question instead: a prefix, a root, or an upward step, any of which
/// leaves the declared root on every platform.
pub(crate) fn escapes(path: &str) -> bool {
    Path::new(path).components().any(|part| {
        matches!(
            part,
            std::path::Component::Prefix(_)
                | std::path::Component::RootDir
                | std::path::Component::ParentDir
        )
    })
}

/// Refuse an `endpoint_contains` map that cannot mean one thing.
///
/// Split out of [`validate`] rather than inlined: the two refusals below are one
/// question about one key, and the enclosing loop already carries five others.
pub(crate) fn validate_endpoint_selectors(source: &Source) -> Result<()> {
    for (name, needle) in &source.endpoint_contains {
        if name.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "mcp: source {:?} declares an `endpoint_contains` entry with a blank name; it \
                 is what a caller types, and an empty one names nothing while reading as \
                 coverage",
                source.id
            )));
        }
        // AN EMPTY NEEDLE IS THE ONE THAT MUST BE REFUSED AT LOAD. `contains`
        // is true of every string for an empty pattern, so the selector would
        // match the entire server map and turn the row into first-wins over
        // everything — the precise failure `Ambiguous` exists to prevent,
        // tripped on every call rather than reported once here.
        if needle.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "mcp: source {:?} maps {name:?} to an empty endpoint substring; every address \
                 contains it, so the name would select whichever server the wiring file \
                 happens to list first",
                source.id
            )));
        }
    }
    Ok(())
}
