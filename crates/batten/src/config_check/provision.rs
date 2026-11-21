use crate::config_model::{Provision, Unpack};
use crate::error::UsageError;

use anyhow::Result;

use std::path::Path;

/// This host's platform key: `<os>-<arch>`, e.g. `linux-x86_64`.
///
/// Read off [`std::env::consts`], which is what the compiled binary knows about
/// itself. See [`Provision::platforms`] for why this rather than a target triple.
#[must_use]
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// Validate the manifest at load.
///
/// # Errors
///
/// Returns a [`UsageError`] (→ exit `1`) for a duplicate name, an empty required
/// field, or a checksum that is not 64 hex characters. A malformed pin is worth
/// refusing at load rather than at fetch time: it can never match, so every
/// apply would fail with a mismatch that blames the artifact for a typo in the
/// config.
pub fn validate(entries: &[Provision]) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for entry in entries {
        for (key, value) in [
            ("name", &entry.name),
            ("version", &entry.version),
            ("binary", &entry.binary),
        ] {
            if value.trim().is_empty() {
                return Err(UsageError::raise(format!(
                    "provision: `{key}` must not be empty"
                )));
            }
        }
        if seen.contains(&entry.name.as_str()) {
            return Err(UsageError::raise(format!(
                "provision {}: declared twice; each entry owns its own cache path",
                entry.name
            )));
        }
        seen.push(&entry.name);

        validate_artifact_spelling(entry)?;
        validate_subtree(entry)?;
    }
    Ok(())
}

/// `strip` and `bin`, on the entry and on each platform row (CLOUD-2682).
///
/// Refused at load: either key where nothing is unpacked; `strip` without
/// `bin`; a `bin` that is empty, absolute or climbs with `..`; and `bin` with
/// `link` where the launcher, a `#!` file, cannot run.
pub(crate) fn validate_subtree(entry: &Provision) -> Result<()> {
    let mut rows: Vec<(&str, Unpack, Option<usize>, Option<&str>)> = Vec::new();
    if entry.platforms.is_empty() {
        rows.push(("the entry", entry.unpack, entry.strip, entry.bin.as_deref()));
    }
    for (key, artifact) in &entry.platforms {
        rows.push((
            key.as_str(),
            artifact.unpack.unwrap_or(entry.unpack),
            artifact.strip.or(entry.strip),
            artifact.bin.as_deref().or(entry.bin.as_deref()),
        ));
    }
    let refuse = |row: &str, why: &str| {
        Err(UsageError::raise(format!(
            "provision {}: {row}: {why}",
            entry.name
        )))
    };
    for (row, unpack, strip, bin) in rows {
        if (strip.is_some() || bin.is_some()) && unpack == Unpack::None {
            return refuse(
                row,
                "`strip` and `bin` extract from an archive, and this row unpacks none",
            );
        }
        if strip.is_some() && bin.is_none() {
            return refuse(row, "`strip` shapes a subtree, and only `bin` asks for one");
        }
        let Some(bin) = bin else {
            continue;
        };
        let path = Path::new(bin);
        let climbs = path
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)));
        if bin.trim().is_empty() || path.is_absolute() || climbs {
            return refuse(
                row,
                "`bin` is a relative path inside the archive, with no `..`",
            );
        }
        if entry.link.is_some() && cfg!(not(unix)) {
            return refuse(
                row,
                "a subtree's `link` is a `#!` launcher, which this host cannot run",
            );
        }
    }
    Ok(())
}

/// The `url`/`sha256`-versus-`platforms` xor, plus every checksum's shape.
///
/// Refused at load for the same reason a malformed checksum is: an entry
/// spelling both, or neither, can never install anything, so every apply would
/// fail with a message about the artifact rather than about the config.
pub(crate) fn validate_artifact_spelling(entry: &Provision) -> Result<()> {
    // `url` and `sha256` are one spelling in two fields, so a half-written pair
    // is its own error — reporting it as "no artifact" would send the author
    // looking for a platform table they never meant to write.
    match (entry.url.as_ref(), entry.sha256.as_ref()) {
        (Some(_), None) | (None, Some(_)) => {
            return Err(UsageError::raise(format!(
                "provision {}: `url` and `sha256` are a pair; declare both or neither",
                entry.name
            )));
        }
        _ => {}
    }

    let single = entry.url.is_some();
    let table = !entry.platforms.is_empty();
    if single && table {
        return Err(UsageError::raise(format!(
            "provision {}: declares both a single `url` and a `[provision.platforms]` table; \
             exactly one, or two pins could disagree about what this host installs",
            entry.name
        )));
    }
    if !single && !table {
        return Err(UsageError::raise(format!(
            "provision {}: declares no artifact; give it a `url` + `sha256`, or a \
             `[provision.platforms]` table keyed `<os>-<arch>` (this host is {})",
            entry.name,
            platform_key()
        )));
    }

    if let (Some(url), Some(sha256)) = (entry.url.as_ref(), entry.sha256.as_ref()) {
        check_url(&entry.name, "url", url)?;
        check_sha256(&entry.name, "sha256", sha256)?;
    }
    for (platform, artifact) in &entry.platforms {
        if platform.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "provision {}: a platform key must not be empty",
                entry.name
            )));
        }
        check_url(&entry.name, platform, &artifact.url)?;
        check_sha256(&entry.name, platform, &artifact.sha256)?;
    }
    validate_env(entry)
}

/// The `prepend_list`-versus-`from_first_set` xor on every `[[provision.env]]` row.
///
/// Refused at LOAD, on the same argument the artifact xor above is: a row
/// spelling neither sets nothing, and a launcher that silently sets nothing is
/// byte-identical to one that was never written — which is the failure this whole
/// field exists to end rather than to reproduce one layer down. A row spelling
/// both would have two rules for one variable and no stated precedence.
pub(crate) fn validate_env(entry: &Provision) -> Result<()> {
    for rule in &entry.env {
        if rule.name.trim().is_empty() {
            return Err(UsageError::raise(format!(
                "provision {}: an `[[provision.env]]` row must name a variable",
                entry.name
            )));
        }
        // A REMOVAL IS THE THIRD SHAPE, and it is the one the "declares nothing"
        // arm below would otherwise refuse. `unset` states an outcome rather
        // than a source, so it is complete on its own and pairing it with a
        // source would be two rules for one variable with no order between them
        // — the same fault the first arm names (CLOUD-1569).
        if rule.unset {
            if !rule.prepend_list.is_empty() || !rule.from_first_set.is_empty() {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares `unset` beside a source; a row \
                     either removes the variable or decides its value, and one \
                     carrying both says nothing about which wins",
                    entry.name, rule.name
                )));
            }
            if rule.reject_prefix.is_some() {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares `unset` beside `reject_prefix`; \
                     the prefix filters CANDIDATES, and a row that keeps none has \
                     nothing to filter",
                    entry.name, rule.name
                )));
            }
            continue;
        }
        if rule.reject_prefix.is_some() && rule.from_first_set.is_empty() {
            return Err(UsageError::raise(format!(
                "provision {}: env {} declares `reject_prefix` with no \
                 `from_first_set`; the prefix decides which CANDIDATE is real, so a \
                 row with no candidates applies it to nothing",
                entry.name, rule.name
            )));
        }
        match (rule.prepend_list.is_empty(), rule.from_first_set.is_empty()) {
            (false, false) => {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares both `prepend_list` and \
                     `from_first_set`; exactly one, or two rules decide one variable \
                     with no stated order between them",
                    entry.name, rule.name
                )));
            }
            (true, true) => {
                return Err(UsageError::raise(format!(
                    "provision {}: env {} declares neither `prepend_list`, \
                     `from_first_set` nor `unset`, so it would set nothing — and a \
                     launcher that sets nothing cannot be told from one that was \
                     never written",
                    entry.name, rule.name
                )));
            }
            _ => {}
        }
    }
    Ok(())
}

pub(crate) fn check_url(name: &str, where_: &str, url: &str) -> Result<()> {
    if url.trim().is_empty() {
        return Err(UsageError::raise(format!(
            "provision {name}: `{where_}` has an empty url"
        )));
    }
    Ok(())
}

pub(crate) fn check_sha256(name: &str, where_: &str, sha256: &str) -> Result<()> {
    if sha256.len() != 64 || !sha256.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(UsageError::raise(format!(
            "provision {name}: `{where_}` sha256 must be 64 hex characters"
        )));
    }
    Ok(())
}
