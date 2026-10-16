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
//! It reaches one thing in the crate, `durable`, for the write. It is plumbing
//! that a `fix` calls, so it is placed below every decider.

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
    /// An array of strings: a row's `except` list (CLOUD-2290), the first
    /// structured value a consumer of this seam needed.
    Strings(Vec<String>),
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
    /// Apply `edits`, each a [`Edit::Set`] or [`Edit::Remove`] addressed from
    /// the row, inside the one row of the array of tables `array` whose `id` is
    /// `id` (CLOUD-2290). A key path cannot address a `[[rule]]` row, because
    /// the rows share one key and are told apart by a value.
    ///
    /// No row, or more than one, with that `id` is refused rather than guessed.
    InRow {
        /// The array of tables, as `rule` for `[[rule]]`.
        array: String,
        /// The `id` value naming the row.
        id: String,
        /// What is applied inside it.
        edits: Vec<Edit>,
    },
    /// Append a new row to the array of tables `array`, carrying `fields` in
    /// order. It renders at the end of the file, after every table already
    /// there, so it can never land between another row and that row's own
    /// nested tables.
    AppendRow {
        /// The array of tables, as `rule` for `[[rule]]`.
        array: String,
        /// The row's keys and values, in the order they are written.
        fields: Vec<(String, Scalar)>,
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
    // Through `durable::replace` (temp, fsync, rename): a repair that a crash
    // leaves half-written has destroyed the file it was meant to fix.
    crate::durable::replace(path, edited)
        .with_context(|| format!("writing `{}`", path.display()))?;
    Ok(true)
}

fn toml(source: &str, edits: &[Edit]) -> Result<String> {
    let mut doc: DocumentMut = source
        .parse()
        .context("the source does not parse as TOML")?;
    for edit in edits {
        match edit {
            Edit::Set { path, value } => set(doc.as_table_mut(), path, value)?,
            Edit::Remove { path } => remove(doc.as_table_mut(), path)?,
            Edit::InRow { array, id, edits } => {
                let rows = rows_mut(&mut doc, array)?;
                let index = row_index(rows, array, id)?;
                let row = rows
                    .get_mut(index)
                    .with_context(|| format!("no `[[{array}]]` row has id `{id}`"))?;
                for edit in edits {
                    match edit {
                        Edit::Set { path, value } => set(row, path, value)?,
                        Edit::Remove { path } => remove(row, path)?,
                        Edit::InRow { .. } | Edit::AppendRow { .. } => {
                            bail!("an edit inside a row addresses a key, never another row")
                        }
                    }
                }
            }
            Edit::AppendRow { array, fields } => {
                let position = last_position(doc.as_table()).map_or(0, |last| last + 1);
                let mut row = toml_edit::Table::new();
                for (key, value) in fields {
                    row.insert(key, Item::Value(value_of(value)));
                }
                row.set_position(Some(position));
                match doc.get_mut(array) {
                    None => {
                        let mut rows = toml_edit::ArrayOfTables::new();
                        rows.push(row);
                        doc.insert(array, Item::ArrayOfTables(rows));
                    }
                    Some(item) => item
                        .as_array_of_tables_mut()
                        .with_context(|| format!("`{array}` is not an array of tables"))?
                        .push(row),
                }
            }
        }
    }
    Ok(render(&doc))
}

fn rows_mut<'a>(doc: &'a mut DocumentMut, array: &str) -> Result<&'a mut toml_edit::ArrayOfTables> {
    doc.get_mut(array)
        .and_then(Item::as_array_of_tables_mut)
        .with_context(|| format!("`{array}` is not an array of tables"))
}

fn row_index(rows: &toml_edit::ArrayOfTables, array: &str, id: &str) -> Result<usize> {
    let matching: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| row.get("id").and_then(Item::as_str) == Some(id))
        .map(|(index, _)| index)
        .collect();
    match matching.as_slice() {
        [one] => Ok(*one),
        [] => bail!("no `[[{array}]]` row has id `{id}`"),
        _ => bail!("{} `[[{array}]]` rows have id `{id}`", matching.len()),
    }
}

/// The greatest document position any table under `table` holds.
///
/// A table with no position renders beside the last positioned one before it,
/// which for an appended row is the previous row — and that row's own nested
/// tables come after it, so they would read as the new row's. Positioning the
/// new row past every table is what keeps the append from adopting them.
fn last_position(table: &toml_edit::Table) -> Option<isize> {
    let mut last = table.position();
    for (_, item) in table {
        let nested = match item {
            Item::Table(inner) => last_position(inner),
            Item::ArrayOfTables(rows) => rows.iter().filter_map(last_position).max(),
            Item::None | Item::Value(_) => None,
        };
        last = last.max(nested);
    }
    last
}

fn value_of(value: &Scalar) -> Value {
    match value {
        Scalar::Bool(flag) => Value::from(*flag),
        Scalar::Integer(number) => Value::from(*number),
        Scalar::String(text) => Value::from(text.as_str()),
        Scalar::Strings(texts) => Value::Array(texts.iter().map(String::as_str).collect()),
    }
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

/// Replace `existing` with `new`, keeping the existing value's decor (the space
/// after `=` and any trailing comment) so that only the value itself changes.
///
/// The one spelling of that rule, for [`set`] and for every other TOML writer
/// that edits a value in place (`engine update`, CLOUD-2279).
pub(crate) fn replace_value(existing: &mut toml_edit::Value, new: toml_edit::Value) {
    let decor = existing.decor().clone();
    *existing = new;
    *existing.decor_mut() = decor;
}

fn set(root: &mut toml_edit::Table, path: &[String], value: &Scalar) -> Result<()> {
    let (parents, leaf) = split(path)?;
    let mut table: &mut dyn toml_edit::TableLike = root;
    for key in parents {
        // A missing key becomes a table, and a scalar in the path is refused
        // rather than overwritten.
        let item = table.entry(key.as_str()).or_insert_with(toml_edit::table);
        table = item
            .as_table_like_mut()
            .with_context(|| format!("`{key}` is under a key that is not a table"))?;
    }
    let new = value_of(value);
    match table.get_mut(leaf) {
        Some(Item::Value(existing)) => replace_value(existing, new),
        Some(Item::None) | None => {
            table.insert(leaf, Item::Value(new));
        }
        Some(_) => bail!("`{leaf}` is a table, not a value"),
    }
    Ok(())
}

fn remove(root: &mut toml_edit::Table, path: &[String]) -> Result<()> {
    let (parents, leaf) = split(path)?;
    let mut table: &mut dyn toml_edit::TableLike = root;
    for key in parents {
        let Some(next) = table.get_mut(key) else {
            return Ok(());
        };
        table = next
            .as_table_like_mut()
            .with_context(|| format!("`{key}` is under a key that is not a table"))?;
    }
    table.remove(leaf);
    Ok(())
}
