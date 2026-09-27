//! Format-preserving edits to a committed config file (CLOUD-1575).
//!
//! # Why this exists
//!
//! [`crate::rules`]'s `fix` column is the MUTATING half of §9's duality: the
//! command that repairs what `check` condemned. Measured on `main` when this
//! module landed, zero rules declared one and thirty-five declared a
//! `no_fix_reason` instead. That is a missing substrate rather than missing
//! authorship: most findings are repaired by editing a committed config file, and
//! the crate could only write one back by destroying it. `toml` is serde-shaped,
//! so a round-trip through its `Value` drops every comment and blank line and
//! re-sorts every key. A repair that reformats the file it repairs is a repair
//! nobody runs twice.
//!
//! # The contract, and the one case that holds it
//!
//! **The output differs from the input only at the edited key.** Every byte
//! outside it, including comments, blank lines, key order, quoting and the
//! whitespace around `=`, is the input's own. An edit that changes nothing
//! returns the input byte for byte, which is what makes a `fix` idempotent
//! rather than merely convergent.
//!
//! `tests/it/config_edit.rs` pins that contract against a fixture built to break
//! it, and carries the negative control: the same edit pushed through a
//! `toml::Value` round-trip fails the same predicate. A case that only asserted
//! "the key now has the new value" would pass on both, so it would bind
//! assignment rather than preservation.
//!
//! # One seam, sibling backends
//!
//! [`Format`] is the dispatch, and a second format is a new variant with its own
//! backend rather than a rewrite. TOML is the only one today. YAML is the natural
//! second, and it is deliberately NOT assumed: `yaml-rust2`'s emitter has to be
//! measured against this contract before it is trusted with it, not after.
//!
//! # Effect
//!
//! [`apply`] is pure: text in, text out. [`apply_file`] is the `write` effect.
//! It belongs to a `fix` running under `enforce`, never to `check`, which is
//! declared `read`.
//!
//! This module reaches nothing else in the crate. It is plumbing that a `fix`
//! calls, so it is placed below every decider.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, Result, bail};
use toml_edit::{DocumentMut, Item, Value};

/// The file format an edit is applied in: one variant per backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Format {
    /// TOML, through `toml_edit`'s format-preserving document.
    Toml,
}

/// A value an edit writes.
///
/// Scalars only, because every `fix` this seam was built for writes one: a
/// `workspace = true`, a lint level raised from `deny` to `forbid`, a pin. A
/// structured value is a variant somebody adds with the consumer that needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scalar {
    /// `true` or `false`.
    Bool(bool),
    /// A signed integer.
    Integer(i64),
    /// A string, rendered in the backend's default quoting.
    String(String),
}

/// One edit, addressed by a key path from the document root.
///
/// A path is a sequence of keys rather than a dotted string, so a key that
/// itself contains a `.` (a quoted TOML key) needs no escaping rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Edit {
    /// Write `value` at `path`, creating any missing table on the way.
    ///
    /// An existing value keeps its surrounding whitespace and trailing comment.
    /// Only the value itself is replaced.
    Set {
        /// The keys from the root to the one written.
        path: Vec<String>,
        /// What is written there.
        value: Scalar,
    },
    /// Remove the key at `path`. A key that is already absent is not an error,
    /// so a repair can run twice.
    Remove {
        /// The keys from the root to the one removed.
        path: Vec<String>,
    },
}

/// Apply `edits`, in order, to `source`, and return the edited text.
///
/// # Errors
///
/// When `source` does not parse as `format`, when an edit names an empty path,
/// or when a path runs through something that is not a table, such as a scalar
/// or an array of tables. Nothing is partially applied: the caller gets either
/// the whole edited text or an error.
pub fn apply(format: Format, source: &str, edits: &[Edit]) -> Result<String> {
    match format {
        Format::Toml => toml(source, edits),
    }
}

/// Apply `edits` to the file at `path`, and write it back only if it changed.
///
/// Returns whether the file was written. An edit set that changes nothing leaves
/// the file untouched, including its modification time.
///
/// # Errors
///
/// When the file cannot be read or written, or for any reason [`apply`]
/// refuses. A refused edit writes nothing.
pub fn apply_file(format: Format, path: &Path, edits: &[Edit]) -> Result<bool> {
    let source =
        fs::read_to_string(path).with_context(|| format!("reading `{}`", path.display()))?;
    let edited = apply(format, &source, edits)?;
    if edited == source {
        return Ok(false);
    }
    fs::write(path, edited).with_context(|| format!("writing `{}`", path.display()))?;
    Ok(true)
}

fn toml(source: &str, edits: &[Edit]) -> Result<String> {
    let mut doc: DocumentMut = source
        .parse()
        .context("the source does not parse as TOML")?;
    for edit in edits {
        match edit {
            Edit::Set { path, value } => set(&mut doc, path, value)?,
            Edit::Remove { path } => remove(&mut doc, path)?,
        }
    }
    Ok(render(&doc))
}

/// The document as text.
///
/// **This single line carries the whole contract**, which is why it is a
/// function of its own. `DocumentMut` renders every byte it was not asked to
/// change exactly as it read it. A `toml::Value` round-trip in its place
/// type-checks, still writes the right value at the right key, and destroys
/// everything else.
//MUTANT-SUITE crates/batten/tests/it/config_edit.rs
//MUTANT config-edit-toml-roundtrip|s@^    doc.to_string()$@    toml::to_string(\&toml::from_str::<toml::Table>(\&doc.to_string()).unwrap_or_default()).unwrap_or_default()@|an_edit_changes_only_the_edited_key
fn render(doc: &DocumentMut) -> String {
    doc.to_string()
}

fn split(path: &[String]) -> Result<(&[String], &str)> {
    let Some((leaf, parents)) = path.split_last() else {
        bail!("an edit names no key");
    };
    Ok((parents, leaf.as_str()))
}

fn set(doc: &mut DocumentMut, path: &[String], value: &Scalar) -> Result<()> {
    let (parents, leaf) = split(path)?;
    let mut item = doc.as_item_mut();
    for key in parents {
        // Indexing a missing key creates a table, and indexing a scalar would
        // panic. So the parent is checked first, and a scalar in the path is
        // refused rather than overwritten.
        if !(item.is_none() || item.is_table_like()) {
            bail!("`{key}` is under a key that is not a table");
        }
        item = &mut item[key.as_str()];
    }
    if item.is_none() {
        *item = toml_edit::table();
    }
    let table = item
        .as_table_like_mut()
        .with_context(|| format!("`{leaf}` is under a key that is not a table"))?;
    let new = match value {
        Scalar::Bool(flag) => Value::from(*flag),
        Scalar::Integer(number) => Value::from(*number),
        Scalar::String(text) => Value::from(text.as_str()),
    };
    match table.get_mut(leaf) {
        Some(Item::Value(existing)) => {
            // Keep the existing value's decor (the space after `=` and any
            // trailing comment) so that only the value itself changes.
            let decor = existing.decor().clone();
            *existing = new;
            *existing.decor_mut() = decor;
        }
        Some(Item::None) | None => {
            table.insert(leaf, Item::Value(new));
        }
        Some(_) => bail!("`{leaf}` is a table, not a value"),
    }
    Ok(())
}

fn remove(doc: &mut DocumentMut, path: &[String]) -> Result<()> {
    let (parents, leaf) = split(path)?;
    let mut item = doc.as_item_mut();
    for key in parents {
        let table = item
            .as_table_like_mut()
            .with_context(|| format!("`{key}` is under a key that is not a table"))?;
        let Some(next) = table.get_mut(key) else {
            return Ok(());
        };
        item = next;
    }
    let table = item
        .as_table_like_mut()
        .with_context(|| format!("`{leaf}` is under a key that is not a table"))?;
    table.remove(leaf);
    Ok(())
}
